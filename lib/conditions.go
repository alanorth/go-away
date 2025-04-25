package lib

import (
	http_cel "codeberg.org/gone/http-cel"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"log/slog"
	"net"
)

func (state *State) initConditions() (err error) {
	state.programEnv, err = http_cel.NewEnvironment(

		cel.Variable("fp", cel.MapType(cel.StringType, cel.StringType)),
		cel.Function("inDNSBL",
			cel.Overload("inDNSBL_ip",
				[]*cel.Type{cel.AnyType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					slog.Error("inDNSBL function has been deprecated, replace with dnsbl challenge")
					return types.Bool(false)
				}),
			),
		),

		cel.Function("network",
			cel.MemberOverload("netIP_network_string",
				[]*cel.Type{cel.BytesType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					var ip net.IP
					switch v := lhs.Value().(type) {
					case []byte:
						ip = v
					case net.IP:
						ip = v
					}

					if ip == nil {
						panic(fmt.Errorf("invalid ip %v", lhs.Value()))
					}

					val, ok := rhs.Value().(string)
					if !ok {
						panic(fmt.Errorf("invalid network value %v", rhs.Value()))
					}

					network, ok := state.networks[val]
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

		cel.Function("inNetwork",
			cel.Overload("inNetwork_string_ip",
				[]*cel.Type{cel.StringType, cel.BytesType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					var ip net.IP
					switch v := rhs.Value().(type) {
					case []byte:
						ip = v
					case net.IP:
						ip = v
					}

					if ip == nil {
						panic(fmt.Errorf("invalid ip %v", rhs.Value()))
					}

					val, ok := lhs.Value().(string)
					if !ok {
						panic(fmt.Errorf("invalid value %v", lhs.Value()))
					}
					slog.Debug(fmt.Sprintf("inNetwork function has been deprecated and will be removed in a future release, use remoteAddress.network(\"%s\") instead", val))

					network, ok := state.networks[val]
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
