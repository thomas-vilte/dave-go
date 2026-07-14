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
//
// Channel moves (follow mode): the harness handles the two move cases a real
// music bot has to deal with, exercising the full dave-go session lifecycle
// (Close the discarded session → fresh conn → fresh session via the hook →
// new MLS group and epoch authenticator code in the new channel):
//
//   - The bot gets dragged to another channel: disgo does not recover from a
//     forced move (the voice gateway dies with 4014/4006), so the harness
//     tears the dead conn down and rejoins the channel it was moved to.
//   - DISCORD_FOLLOW_USER_ID is set and that user switches channel: the bot
//     follows them.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
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
	token        = os.Getenv("DISCORD_TOKEN")
	guildID      = snowflake.GetEnv("DISCORD_GUILD_ID")
	channelID    = snowflake.GetEnv("DISCORD_CHANNEL_ID")
	followUserID = snowflake.GetEnv("DISCORD_FOLLOW_USER_ID") // optional: user the bot follows across channels
	dcaFile      = envOrDefault("DCA_FILE", "./nico.dca")
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

// mover owns the voice connection lifecycle: the initial join, following the
// followed user across channels, and recovering when the bot itself gets
// dragged. Every move runs the same teardown the disgo issue asks the library
// to automate: Close() the discarded dave session, close the dead conn, open
// a fresh one (which delivers a fresh session through the create-func hook).
type mover struct {
	client *bot.Client
	holder *sessionHolder

	// stateMu guards the fields below with short critical sections only, so
	// disgo's event dispatcher never blocks behind a slow conn teardown.
	stateMu sync.Mutex
	botUser snowflake.ID
	target  snowflake.ID // channel the bot is in (or is currently joining)
	moving  bool         // true while a teardown+rejoin is in flight

	// moveMu serializes whole move operations (teardown + reopen).
	moveMu sync.Mutex
}

func (m *mover) onReady(e *events.Ready) {
	m.stateMu.Lock()
	m.botUser = e.User.ID
	m.target = channelID
	m.stateMu.Unlock()

	go m.connectAndPlay(channelID)
}

func (m *mover) onVoiceStateUpdate(e *events.GuildVoiceStateUpdate) {
	vs := e.VoiceState
	if vs.GuildID != guildID {
		return
	}

	m.stateMu.Lock()
	botUser, target, moving := m.botUser, m.target, m.moving
	m.stateMu.Unlock()

	switch vs.UserID {
	case botUser:
		if vs.ChannelID == nil {
			if !moving {
				slog.Info("bot disconnected from voice; not rejoining (restart the harness or move the followed user)")
			}

			return
		}
		if *vs.ChannelID == target {
			return // ack of our own join/move
		}
		slog.Info("bot was dragged to another channel; rejoining there",
			slog.String("new_channel", vs.ChannelID.String()))
		go m.moveTo(*vs.ChannelID)
	case followUserID:
		if vs.ChannelID == nil || *vs.ChannelID == target {
			return
		}
		slog.Info("followed user changed channel; moving the bot",
			slog.String("new_channel", vs.ChannelID.String()))
		go m.moveTo(*vs.ChannelID)
	}
}

// moveTo tears down the current voice conn and joins newChannel. This is the
// lifecycle a production bot must run on every move (until disgo closes the
// session itself, see the io.Closer issue): close the dave session FIRST so
// its recovery watchdogs die now instead of up to ~45s later, then replace
// the conn.
func (m *mover) moveTo(newChannel snowflake.ID) {
	m.moveMu.Lock()
	defer m.moveMu.Unlock()

	m.stateMu.Lock()
	if m.target == newChannel {
		m.stateMu.Unlock()

		return
	}
	m.target = newChannel
	m.moving = true
	m.stateMu.Unlock()

	if s := m.holder.get(); s != nil {
		_ = s.Close()
		slog.Info("closed dave session of the discarded connection")
	}

	if conn := m.client.VoiceManager.GetConn(guildID); conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn.Close(ctx)
		cancel()
	}

	go m.connectAndPlay(newChannel)
}

// connectAndPlay opens a fresh voice conn to ch and blocks feeding audio into
// it until the conn dies (bot moved/disconnected), at which point it returns
// and the next move re-invokes it.
func (m *mover) connectAndPlay(ch snowflake.ID) {
	conn := m.connect(ch)
	if conn == nil {
		return
	}

	go readUDP(conn)

	// Hold frames during a transient E2EE handshake: Encrypt would fall back
	// to passthrough (plaintext) and E2EE-expecting receivers drop those
	// frames anyway, so sending them just leaks audio and buys nothing.
	hold := func() bool {
		s := m.holder.get()

		return s != nil && s.ShouldHoldFrames()
	}

	for {
		if err := writeOpus(conn.UDP(), hold); err != nil {
			slog.Info("audio loop stopped: udp conn closed (move in progress or bot disconnected)",
				slog.Any("err", err))

			return
		}
	}
}

// connect opens the voice conn and clears the moving flag once the join
// settled (successfully or not) — the flag must only cover the
// teardown+rejoin window, not the whole playback that follows.
func (m *mover) connect(ch snowflake.ID) voice.Conn {
	defer func() {
		m.stateMu.Lock()
		m.moving = false
		m.stateMu.Unlock()
	}()

	conn := m.client.VoiceManager.CreateConn(guildID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Open(ctx, ch, false, false); err != nil {
		slog.Error("error connecting to voice channel", slog.String("channel", ch.String()), slog.Any("err", err))

		return nil
	}
	if err := conn.SetSpeaking(ctx, voice.SpeakingFlagMicrophone); err != nil {
		slog.Error("error setting speaking flag", slog.Any("err", err))

		return nil
	}

	return conn
}

// decryptFailures counts incoming frames the session could not decrypt.
// Bursts right after a join/move are protocol-normal (frames encrypted for
// an epoch the bot was never a member of — it cannot have those keys), so
// they are logged at debug and surfaced as a counter in E2EE STATUS instead
// of spamming warnings. A counter that keeps growing OUTSIDE transition
// windows would be a real problem.
var decryptFailures atomic.Uint64

// readUDP drains incoming packets so decryption stats accumulate. It exits
// when the conn closes; a moved/kicked bot closes the UDP conn permanently,
// and without the ErrClosed check this loop would spin forever logging
// millions of lines.
func readUDP(conn voice.Conn) {
	for {
		if _, err := conn.UDP().ReadPacket(); err != nil {
			switch {
			case errors.Is(err, net.ErrClosed):
				slog.Info("udp read loop exiting: connection closed")

				return
			case errors.Is(err, session.ErrDecryptionFailed):
				// Expected during epoch transitions; the read consumed a
				// packet, so no sleep — sleeping here throttles the drain.
				decryptFailures.Add(1)
				slog.Debug("dropped undecryptable frame (epoch transition window?)", slog.Any("err", err))
			default:
				slog.Warn("error reading udp packet", slog.Any("err", err))
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
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
	if followUserID != 0 {
		slog.Info("follow mode on: the bot will follow this user across channels",
			slog.String("user_id", followUserID.String()))
	}

	holder := &sessionHolder{}
	m := &mover{holder: holder}

	client, err := disgo.New(token,
		bot.WithLogger(logger),
		bot.WithGatewayConfigOpts(gateway.WithIntents(gateway.IntentGuildVoiceStates)),
		bot.WithEventListenerFunc(m.onReady),
		bot.WithEventListenerFunc(m.onVoiceStateUpdate),
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
	m.client = client

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
			slog.Uint64("udp_decrypt_failures", decryptFailures.Load()),
		)
	}
}

// writeOpus reads a local DCA0 file and writes its Opus frames to the voice
// UDP writer, pausing (frames held, file position kept) while hold reports
// true. Returns nil when the file ends (the caller loops it) and the write
// error when the UDP conn fails, so the caller can stop instead of
// re-opening the file in a tight loop against a dead connection.
func writeOpus(w io.Writer, hold func() bool) error {
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
		if hold != nil && hold() {
			continue
		}

		err = binary.Read(file, binary.LittleEndian, &frameLen)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			panic("error reading file: " + err.Error())
		}

		if _, err = io.CopyN(w, file, int64(frameLen)); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return err
		}
	}

	return nil
}
