package lib

import (
	"context"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"log/slog"
	"net"
	"time"
)

func (state *State) initConditions() (err error) {
	state.RulesEnv, err = cel.NewEnv(
		cel.DefaultUTCTimeZone(true),
		cel.Variable("remoteAddress", cel.BytesType),
		cel.Variable("host", cel.StringType),
		cel.Variable("method", cel.StringType),
		cel.Variable("userAgent", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("query", cel.MapType(cel.StringType, cel.StringType)),
		// http.Header
		cel.Variable("headers", cel.MapType(cel.StringType, cel.StringType)),
		//TODO: dynamic type?
		cel.Function("inDNSBL",
			cel.Overload("inDNSBL_ip",
				[]*cel.Type{cel.AnyType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					if state.Settings.DNSBL == nil {
						return types.Bool(false)
					}

					var ip net.IP
					switch v := val.Value().(type) {
					case []byte:
						ip = v
					case net.IP:
						ip = v
					case string:
						ip = net.ParseIP(v)
					}

					if ip == nil {
						panic(fmt.Errorf("invalid ip %v", val.Value()))
					}

					var key [net.IPv6len]byte
					copy(key[:], ip.To16())

					result, ok := state.DecayMap.Get(key)
					if ok {
						return types.Bool(result.Bad())
					}

					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					result, err := state.Settings.DNSBL.Lookup(ctx, ip)
					if err != nil {
						slog.Debug("dnsbl lookup failed", "address", ip.String(), "result", result, "err", err)
					} else {
						slog.Debug("dnsbl lookup", "address", ip.String(), "result", result)
					}
					//TODO: configure decay
					state.DecayMap.Set(key, result, time.Hour)

					return types.Bool(result.Bad())
				}),
			),
		),
		cel.Function("inNetwork",
			cel.Overload("inNetwork_string_ip",
				[]*cel.Type{cel.StringType, cel.AnyType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					var ip net.IP
					switch v := rhs.Value().(type) {
					case []byte:
						ip = v
					case net.IP:
						ip = v
					case string:
						ip = net.ParseIP(v)
					}

					if ip == nil {
						panic(fmt.Errorf("invalid ip %v", rhs.Value()))
					}

					val, ok := lhs.Value().(string)
					if !ok {
						panic(fmt.Errorf("invalid value %v", lhs.Value()))
					}

					network, ok := state.Networks[val]
					if !ok {
						_, ipNet, err := net.ParseCIDR(val)
						if err != nil {
							panic("network not found")
						}
						return types.Bool(ipNet.Contains(ip))
					} else {
						ok, err := network.Contains(ip)
						if err != nil {
							panic(err)
						}
						return types.Bool(ok)
					}
				}),
			),
		),
	)
	if err != nil {
		return err
	}
	return nil
}
