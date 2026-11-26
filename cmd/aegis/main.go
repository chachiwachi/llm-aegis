// aegis: gateway de seguridad para LLMs.
//
//	aegis serve -config aegis.yaml     arranca el gateway
//	aegis scan [-redact] [texto]       analiza un texto (o la entrada estándar)
//	aegis hash-key <clave>             SHA-256 de una API key para la config
//	aegis version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/chachiwachi/llm-aegis/internal/config"
	"github.com/chachiwachi/llm-aegis/internal/engine"
	"github.com/chachiwachi/llm-aegis/internal/gateway"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "scan":
		err = scan(os.Args[2:])
	case "hash-key":
		if len(os.Args) != 3 {
			err = errors.New("uso: aegis hash-key <clave>")
		} else {
			fmt.Println(config.HashKey(os.Args[2]))
		}
	case "version", "-v", "--version":
		fmt.Println("llm-aegis", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `llm-aegis: gateway de seguridad para LLMs

  aegis serve -config aegis.yaml     arranca el gateway
  aegis scan [-redact] [texto]       analiza un texto (o la entrada estándar)
  aegis hash-key <clave>             SHA-256 de una API key para la config
  aegis version`)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "", "fichero de configuración YAML")
	fs.Parse(args)

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eng, err := engine.New(ctx, cfg.EnginePoolSize)
	if err != nil {
		return err
	}
	defer eng.Close(context.Background())

	gw, err := gateway.New(cfg, eng, log)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if cfg.AllowAnonymous {
		log.Warn("allow_anonymous está activado: cualquiera en la red puede usar el gateway")
	}
	log.Info("llm-aegis escuchando", "listen", cfg.Listen, "upstream", cfg.Upstream, "version", version)

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("apagando")
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

func scan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	redact := fs.Bool("redact", false, "devolver también el texto redactado (pii y secret)")
	fs.Parse(args)

	text := strings.Join(fs.Args(), " ")
	if text == "" || text == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		text = string(b)
	}
	ctx := context.Background()
	eng, err := engine.New(ctx, 1)
	if err != nil {
		return err
	}
	defer eng.Close(ctx)

	req := engine.Request{Text: text, Redact: *redact}
	if *redact {
		req.RedactCategories = []string{engine.CategoryPII, engine.CategorySecret}
	}
	res, err := eng.Scan(ctx, req)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(res)
}
