package utils

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func NewServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {

	if tlsConfig == nil {
		proto := new(http.Protocols)
		proto.SetHTTP1(true)
		proto.SetUnencryptedHTTP2(true)
		h1s := &http.Server{
			Handler:   handler,
			Protocols: proto,
		}

		return h1s
	} else {
		server := &http.Server{
			TLSConfig: tlsConfig,
			Handler:   handler,
		}
		return server
	}
}

func EnsureNoOpenRedirect(redirect string) (string, error) {
	uri, err := url.Parse(redirect)
	if err != nil {
		return "", err
	}
	uri.Scheme = ""
	uri.Host = ""
	uri.User = nil
	uri.Opaque = ""
	uri.OmitHost = true

	if uri.Path != "" && !strings.HasPrefix(uri.Path, "/") {
		return "", errors.New("invalid redirect path")
	}

	return uri.String(), nil
}

func MakeReverseProxy(target string) (*httputil.ReverseProxy, error) {
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
		transport.RegisterProtocol("unix", UnixRoundTripper{Transport: transport})
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = transport

	return rp, nil
}
