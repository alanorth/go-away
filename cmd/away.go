package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	go_away "git.gammaspectra.live/git/go-away"
	"gopkg.in/yaml.v3"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
)

func makeReverseProxy(target string) (http.Handler, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	// https://github.com/oauth2-proxy/oauth2-proxy/blob/4e2100a2879ef06aea1411790327019c1a09217c/pkg/upstream/http.go#L124
	if u.Scheme == "unix" {
		// clean path up so we don't use the socket path in proxied requests
		addr := u.Path
		u.Path = ""
		// tell transport how to dial unix sockets
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "unix", addr)
		}
		// tell transport how to handle the unix url scheme
		transport.RegisterProtocol("unix", go_away.UnixRoundTripper{Transport: transport})
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = transport

	return rp, nil
}

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

	slogLevel := flag.String("slog-level", "INFO", "logging level (see https://pkg.go.dev/log/slog#hdr-Levels)")

	target := flag.String("target", "http://localhost:80", "target to reverse proxy to")

	policyFile := flag.String("policy", "", "path to policy YAML file")

	flag.Parse()

	_, _, _, _ = bind, bindNetwork, socketMode, target

	{
		var programLevel slog.Level
		if err := (&programLevel).UnmarshalText([]byte(*slogLevel)); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "invalid log level %s: %v, using info\n", *slogLevel, err)
			programLevel = slog.LevelInfo
		}

		leveler := &slog.LevelVar{}
		leveler.Set(programLevel)

		h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     leveler,
		})
		slog.SetDefault(slog.New(h))
	}

	policyData, err := os.ReadFile(*policyFile)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to read policy file: %w", err))
	}

	var policy go_away.Policy

	if err = yaml.Unmarshal(policyData, &policy); err != nil {
		log.Fatal(fmt.Errorf("failed to parse policy file: %w", err))
	}

	backend, err := makeReverseProxy(*target)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to create reverse proxy for %s: %w", *target, err))
	}

	state, err := go_away.NewState(policy, "git.gammaspectra.live/git/go-away/cmd", backend)

	if err != nil {
		log.Fatal(fmt.Errorf("failed to create state: %w", err))
	}

	listener, listenUrl := setupListener(*bindNetwork, *bind, *socketMode)
	slog.Info(
		"listening",
		"url", listenUrl,
		"target", *target,
	)

	server := http.Server{
		Handler: state,
	}

	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
