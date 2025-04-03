package main

import (
	"errors"
	"flag"
	"fmt"
	"git.gammaspectra.live/git/go-away/lib"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"gopkg.in/yaml.v3"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
)

func setupListener(network, address, socketMode string) (net.Listener, string) {
	formattedAddress := ""
	switch network {
	case "unix":
		formattedAddress = "unix:" + address
	case "tcp":
		formattedAddress = "http://localhost" + address
	default:
		formattedAddress = fmt.Sprintf(`(%s) %s`, network, address)
	}

	listener, err := net.Listen(network, address)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to bind to %s: %w", formattedAddress, err))
	}

	// additional permission handling for unix sockets
	if network == "unix" {
		mode, err := strconv.ParseUint(socketMode, 8, 0)
		if err != nil {
			listener.Close()
			log.Fatal(fmt.Errorf("could not parse socket mode %s: %w", socketMode, err))
		}

		err = os.Chmod(address, os.FileMode(mode))
		if err != nil {
			listener.Close()
			log.Fatal(fmt.Errorf("could not change socket mode: %w", err))
		}
	}

	return listener, formattedAddress
}

func main() {
	bind := flag.String("bind", ":8080", "network address to bind HTTP to")
	bindNetwork := flag.String("bind-network", "tcp", "network family to bind HTTP to, e.g. unix, tcp")
	socketMode := flag.String("socket-mode", "0770", "socket mode (permissions) for unix domain sockets.")

	slogLevel := flag.String("slog-level", "WARN", "logging level (see https://pkg.go.dev/log/slog#hdr-Levels)")
	debug := flag.Bool("debug", false, "debug mode with logs and server timings")

	policyFile := flag.String("policy", "", "path to policy YAML file")
	challengeTemplate := flag.String("challenge-template", "anubis", "name or path of the challenge template to use (anubis, forgejo)")
	challengeTemplateTheme := flag.String("challenge-template-theme", "", "name of the challenge template theme to use (forgejo => [forgejo-dark, forgejo-light, gitea...])")

	flag.Parse()

	{
		var programLevel slog.Level
		if err := (&programLevel).UnmarshalText([]byte(*slogLevel)); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "invalid log level %s: %v, using info\n", *slogLevel, err)
			programLevel = slog.LevelInfo
		}

		leveler := &slog.LevelVar{}
		leveler.Set(programLevel)

		h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: *debug,
			Level:     leveler,
		})
		slog.SetDefault(slog.New(h))
	}

	policyData, err := os.ReadFile(*policyFile)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to read policy file: %w", err))
	}

	var p policy.Policy

	if err = yaml.Unmarshal(policyData, &p); err != nil {
		log.Fatal(fmt.Errorf("failed to parse policy file: %w", err))
	}

	state, err := lib.NewState(p, lib.StateSettings{
		Debug:                  *debug,
		PackagePath:            "git.gammaspectra.live/git/go-away/cmd",
		ChallengeTemplate:      *challengeTemplate,
		ChallengeTemplateTheme: *challengeTemplateTheme,
	})

	if err != nil {
		log.Fatal(fmt.Errorf("failed to create state: %w", err))
	}

	listener, listenUrl := setupListener(*bindNetwork, *bind, *socketMode)
	slog.Warn(
		"listening",
		"url", listenUrl,
	)

	server := http.Server{
		Handler: state,
	}

	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
