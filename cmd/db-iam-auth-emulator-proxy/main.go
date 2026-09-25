package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/moriyoshi/db-iam-auth-emulator-proxy/iamproxy"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML configuration")
	validate := flag.Bool("validate", false, "validate configuration and exit")
	flag.Parse()
	c, err := iamproxy.LoadConfig(*configPath)
	if err == nil && c.TLSCert == "" {
		err = fmt.Errorf("%s: TLS certificate and key are required", *configPath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *validate {
		fmt.Println("configuration valid")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	e, err := iamproxy.Start(ctx, c, iamproxy.Options{Logger: slog.Default()})
	if err != nil {
		slog.Error("start", "err", err)
		os.Exit(1)
	}
	<-e.Done()
}
