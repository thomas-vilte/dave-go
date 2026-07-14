// Command interop runs a DAVE bot with full E2EE observability so its interop
// against a real Discord client can be verified objectively (not by "it seems
// to work"). It plays a local DCA (Opus) file into a voice channel and, every
// few seconds, logs the session's E2EE state, cumulative stats, and — most
// importantly — the epoch authenticator displayable code.
//
// How to verify interop (see README.md for the full checklist):
//
//  1. Run this bot; join the SAME voice channel with a real Discord client.
//  2. Media layer: you should HEAR the DCA audio. If you do, the bot's DAVE
//     frames are valid and decryptable by the official client.
//  3. MLS layer: open the call's E2EE / "voice privacy" details in the Discord
//     client and compare the displayed security code with the
//     "epoch_authenticator_code" this bot logs. A match is cryptographic proof
//     that the bot and the client share the same MLS group at the same epoch.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/disgoorg/disgo"
	"github.com/disgoorg/disgo/bot"
	"github.com/disgoorg/disgo/events"
	"github.com/disgoorg/disgo/gateway"
	"github.com/disgoorg/disgo/voice"
	"github.com/disgoorg/snowflake/v2"
	"github.com/thomas-vilte/dave-go/session"
)

var (
	token     = os.Getenv("DISCORD_TOKEN")
	guildID   = snowflake.GetEnv("DISCORD_GUILD_ID")
	channelID = snowflake.GetEnv("DISCORD_CHANNEL_ID")
	dcaFile   = envOrDefault("DCA_FILE", "./nico.dca")
)

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}

// logLevel reads LOG_LEVEL (debug/info/warn/error), defaulting to info.
func logLevel() slog.Level {
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// sessionHolder stashes the *session.Session handed over at creation so the
// status goroutine can read the live E2EE state. There is one DAVE session
// per voice connection; a move/reconnect replaces it, so guard with a mutex
// and always read the latest.
type sessionHolder struct {
	mu sync.Mutex
	s  *session.Session
}

func (h *sessionHolder) set(s *session.Session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.s = s
}

func (h *sessionHolder) get() *session.Session {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.s
}

func main() {
	// LOG_LEVEL controls verbosity: "info" (default) keeps the interop status
	// lines readable; "debug" adds the full MLS/transition trace (op22/op29
	// handlers, epoch activation) — needed to diagnose a stuck transition.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel(),
	}))
	slog.SetDefault(logger)

	slog.Info("starting interop harness", slog.String("disgo_version", disgo.Version))

	holder := &sessionHolder{}

	client, err := disgo.New(token,
		bot.WithLogger(logger),
		bot.WithGatewayConfigOpts(gateway.WithIntents(gateway.IntentGuildVoiceStates)),
		bot.WithEventListenerFunc(func(e *events.Ready) {
			go play(e.Client())
		}),
		bot.WithVoiceManagerConfigOpts(
			voice.WithDaveSessionCreateFunc(session.CreateFunc(
				session.WithSessionHook(func(s *session.Session) {
					holder.set(s)
					slog.Info("dave session created — E2EE session captured")
				}),
			)),
		),
	)
	if err != nil {
		slog.Error("error creating client", slog.Any("err", err))

		return
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client.Close(ctx)
	}()

	if err = client.OpenGateway(context.TODO()); err != nil {
		slog.Error("error connecting to gateway", slog.Any("error", err))

		return
	}

	go reportStatus(holder)

	slog.Info("interop harness running. Press CTRL-C to exit.")
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-s
}

// reportStatus logs the session's E2EE state every few seconds: the readiness
// snapshot, key counters, and the epoch authenticator code to compare against
// the Discord client's displayed security code.
func reportStatus(holder *sessionHolder) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		r := holder.get()
		if r == nil {
			continue
		}

		st := r.State()
		stats := r.Stats()

		code := "<none>"
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if c, err := r.EpochAuthenticatorCode(ctx); err == nil {
			code = c
		}
		cancel()

		slog.Info("E2EE STATUS",
			slog.Bool("ready", st.Ready),
			slog.Uint64("protocol_version", uint64(st.ProtocolVersion)),
			slog.Uint64("epoch_id", st.EpochID),
			slog.Bool("degraded", !st.DegradedSince.IsZero()),
			slog.String("epoch_authenticator_code", code),
			slog.Uint64("commits_processed", stats.CommitsProcessed),
			slog.Uint64("welcomes_joined", stats.WelcomesJoined),
			slog.Uint64("encrypt_failures", stats.EncryptFailures),
			slog.Uint64("passthrough_frames", stats.PassthroughFrames),
			slog.Uint64("rejected_replay_frames", stats.RejectedReplayFrames),
			slog.Uint64("downgrade_to_v0", stats.DowngradeToV0),
		)
	}
}

func play(client *bot.Client) {
	conn := client.VoiceManager.CreateConn(guildID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Open(ctx, channelID, false, false); err != nil {
		panic("error connecting to voice channel: " + err.Error())
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		conn.Close(closeCtx)
	}()

	if err := conn.SetSpeaking(ctx, voice.SpeakingFlagMicrophone); err != nil {
		panic("error setting speaking flag: " + err.Error())
	}
	go func() {
		for {
			if _, err := conn.UDP().ReadPacket(); err != nil {
				slog.Warn("error reading udp packet", slog.Any("err", err))
			}
		}
	}()
	for {
		writeOpus(conn.UDP())
	}
}

// writeOpus reads a local DCA0 file and writes its Opus frames to the voice UDP writer.
func writeOpus(w io.Writer) {
	file, err := os.Open(dcaFile)
	if err != nil {
		panic("error opening file: " + err.Error())
	}
	defer func() {
		_ = file.Close()
	}()

	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	var frameLen int16
	for ; true; <-ticker.C {
		err = binary.Read(file, binary.LittleEndian, &frameLen)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}

			panic("error reading file: " + err.Error())
		}

		if _, err = io.CopyN(w, file, int64(frameLen)); err != nil && !errors.Is(err, io.EOF) {
			return
		}
	}
}
