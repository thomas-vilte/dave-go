package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"
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

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	slog.Info("starting up")
	slog.Info("disgo version", slog.String("version", disgo.Version))

	client, err := disgo.New(token,
		bot.WithLogger(logger),
		bot.WithGatewayConfigOpts(gateway.WithIntents(gateway.IntentGuildVoiceStates)),
		bot.WithEventListenerFunc(func(e *events.Ready) {
			go play(e.Client())
		}),
		bot.WithVoiceManagerConfigOpts(
			voice.WithDaveSessionCreateFunc(session.New),
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

	slog.Info("ExampleBot is now running. Press CTRL-C to exit.")
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-s
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
