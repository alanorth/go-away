package settings

import (
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/utils"
	"net/http"
	"net/http/httputil"
	"time"
)

type Backend struct {
	// URL Target server backend path. Supports http/https/unix protocols.
	URL string `yaml:"url"`

	// Host Override the Host header and TLS SNI with this value if specified
	Host string `yaml:"host"`

	//ProxyProtocol uint8 `yaml:"proxy-protocol"`

	// HTTP2Enabled Enable HTTP2 to backend
	HTTP2Enabled bool `yaml:"http2-enabled"`

	// TLSSkipVerify Disable TLS certificate verification, if any
	TLSSkipVerify bool `yaml:"tls-skip-verify"`

	// IpHeader HTTP header to set containing the IP header. Set - to forcefully ignore global defaults.
	IpHeader string `yaml:"ip-header"`

	// GoDNS Resolve URL using the Go DNS server
	// Only relevant when running with CGO enabled
	GoDNS bool `yaml:"go-dns"`

	// Transparent Do not add extra headers onto this backend
	// This prevents GoAway headers from being set, or other state
	Transparent bool `yaml:"transparent"`

	// DialTimeout is the maximum amount of time a dial will wait for
	// a connect to complete.
	//
	// The default is no timeout.
	//
	// When using TCP and dialing a host name with multiple IP
	// addresses, the timeout may be divided between them.
	//
	// With or without a timeout, the operating system may impose
	// its own earlier timeout. For instance, TCP timeouts are
	// often around 3 minutes.
	DialTimeout time.Duration `yaml:"dial-timeout"`

	// TLSHandshakeTimeout specifies the maximum amount of time to
	// wait for a TLS handshake. Zero means no timeout.
	TLSHandshakeTimeout time.Duration `yaml:"tls-handshake-timeout"`

	// IdleConnTimeout is the maximum amount of time an idle
	// (keep-alive) connection will remain idle before closing
	// itself.
	// Zero means no limit.
	IdleConnTimeout time.Duration `yaml:"idle-conn-timeout"`

	// ResponseHeaderTimeout, if non-zero, specifies the amount of
	// time to wait for a server's response headers after fully
	// writing the request (including its body, if any). This
	// time does not include the time to read the response body.
	ResponseHeaderTimeout time.Duration `yaml:"response-header-timeout"`

	// ExpectContinueTimeout, if non-zero, specifies the amount of
	// time to wait for a server's first response headers after fully
	// writing the request headers if the request has an
	// "Expect: 100-continue" header. Zero means no timeout and
	// causes the body to be sent immediately, without
	// waiting for the server to approve.
	// This time does not include the time to send the request header.
	ExpectContinueTimeout time.Duration `yaml:"expect-continue-timeout"`
}

func (b Backend) Create() (*httputil.ReverseProxy, error) {
	if b.IpHeader == "-" {
		b.IpHeader = ""
	}

	proxy, err := utils.MakeReverseProxy(b.URL, b.GoDNS, b.DialTimeout)
	if err != nil {
		return nil, err
	}

	transport := proxy.Transport.(*http.Transport)

	// set transport timeouts
	transport.TLSHandshakeTimeout = b.TLSHandshakeTimeout
	transport.IdleConnTimeout = b.IdleConnTimeout
	transport.ResponseHeaderTimeout = b.ResponseHeaderTimeout
	transport.ExpectContinueTimeout = b.ExpectContinueTimeout

	if b.HTTP2Enabled {
		transport.ForceAttemptHTTP2 = true
	}

	if b.TLSSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	if b.Host != "" {
		transport.TLSClientConfig.ServerName = b.Host
	}

	if b.IpHeader != "" || b.Host != "" || !b.Transparent {
		director := proxy.Director
		proxy.Director = func(req *http.Request) {
			if b.IpHeader != "" && !b.Transparent {
				if ip := utils.GetRemoteAddress(req.Context()); ip != nil {
					req.Header.Set(b.IpHeader, ip.Addr().Unmap().String())
				}
			}
			if b.Host != "" {
				req.Host = b.Host
			}

			if !b.Transparent {
				if data := challenge.RequestDataFromContext(req.Context()); data != nil {
					data.RequestHeaders(req.Header)
				}
			}
			director(req)
		}
	}

	/*if b.ProxyProtocol > 0 {
		dialContext := transport.DialContext
		if dialContext == nil {
			dialContext = (&net.Dialer{}).DialContext
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			addrPort := utils.GetRemoteAddress(ctx)
			if addrPort == nil {
				// pass as is
				hdr := proxyproto.HeaderProxyFromAddrs(b.ProxyProtocol, conn.LocalAddr(), conn.RemoteAddr())
				_, err = hdr.WriteTo(conn)
				if err != nil {
					conn.Close()
					return nil, err
				}
			} else {
				// set proper headers!
				hdr := proxyproto.HeaderProxyFromAddrs(b.ProxyProtocol, net.TCPAddrFromAddrPort(*addrPort), conn.RemoteAddr())
				_, err = hdr.WriteTo(conn)
				if err != nil {
					conn.Close()
					return nil, err
				}
			}
			return conn, nil
		}
	}*/

	proxy.Transport = transport

	return proxy, nil
}
