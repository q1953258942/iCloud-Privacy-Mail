package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"icloud-privacy-mail/internal/app"
)

func main() {
	host := flag.String("host", "127.0.0.1", "bind host")
	port := flag.Int("port", 8787, "bind port")
	configPath := flag.String("config", "config.json", "config file path")
	dataPath := flag.String("data", filepath.Join("data", "state.json"), "state file path")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := app.LoadConfig(*configPath)
	if err != nil {
		logger.Error("load config", "err", err)
		os.Exit(1)
	}
	cfg.Host = firstNonEmpty(*host, cfg.Host)
	if *port != 0 {
		cfg.Port = *port
	}
	cfg.DataPath = firstNonEmpty(*dataPath, cfg.DataPath)

	store, err := app.NewFileStore(cfg.DataPath)
	if err != nil {
		logger.Error("open store", "err", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:           app.NewServer(cfg, store, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	logger.Info("iCloud Privacy Mail panel started", "addr", "http://"+server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
