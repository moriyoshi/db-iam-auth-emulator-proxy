package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/moriyoshi/db-iam-auth-emulator-proxy/internal/e2e"
)

func run(args []string) error {
	f := flag.NewFlagSet("db-iam-auth-emulator-proxy-e2e", flag.ContinueOnError)
	check := f.Bool("check", false, "parse and resolve scenarios without Docker")
	proxy := f.String("proxy", "db-iam-auth-emulator-proxy", "proxy binary")
	fixtureImage := f.String("fixture-image", "db-iam-auth-emulator-proxy-e2e:local", "shared runner and database fixture image")
	timeout := f.Duration("scenario-timeout", 3*time.Minute, "per scenario timeout")
	if err := f.Parse(args); err != nil {
		return err
	}
	paths := f.Args()
	if len(paths) == 0 {
		return errors.New("no scenario files")
	}
	if *check {
		for _, path := range paths {
			if err := e2e.Check(path); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			fmt.Printf("✓ %s parses\n", path)
		}
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	preflight, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := e2e.Preflight(preflight)
	cancel()
	if err != nil {
		return err
	}
	options := e2e.Options{Proxy: *proxy, FixtureImage: *fixtureImage}
	var failed int
	for _, path := range paths {
		fmt.Printf("\n== %s ==\n", path)
		runCtx, cancel := context.WithTimeout(ctx, *timeout)
		err := e2e.New(options, os.Stdout).RunFile(runCtx, path)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", path, err)
			failed++
		} else {
			fmt.Printf("✓ %s passed\n", path)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d scenarios failed", failed)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
