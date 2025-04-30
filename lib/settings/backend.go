package settings

import (
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/utils"
	"net/http"
	"net/http/httputil"
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
}

func (b Backend) Create() (*httputil.ReverseProxy, error) {
	if b.IpHeader == "-" {
		b.IpHeader = ""
	}

	proxy, err := utils.MakeReverseProxy(b.URL, b.GoDNS)
	if err != nil {
		return nil, err
	}

	transport := proxy.Transport.(*http.Transport)

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
				data := challenge.RequestDataFromContext(req.Context())
				if data != nil {
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
