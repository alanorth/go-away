package settings

import (
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
}

func (b Backend) Create() (*httputil.ReverseProxy, error) {
	proxy, err := utils.MakeReverseProxy(b.URL)
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
		director := proxy.Director
		proxy.Director = func(req *http.Request) {
			req.Host = b.Host
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
