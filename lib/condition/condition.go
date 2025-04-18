package condition

import (
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"github.com/yl2chen/cidranger"
	"log/slog"
	"net"
	"strings"
)

type Condition struct {
	Expression *cel.Ast
}

const (
	OperatorOr  = "||"
	OperatorAnd = "&&"
)

func NewRulesEnvironment(networks map[string]cidranger.Ranger) (*cel.Env, error) {

	return cel.NewEnv(
		ext.Strings(
			ext.StringsLocale("en_US"),
			ext.StringsValidateFormatCalls(true),
		),
		cel.DefaultUTCTimeZone(true),
		//TODO: custom type for remoteAddress
		cel.Variable("remoteAddress", cel.BytesType),
		cel.Variable("host", cel.StringType),
		cel.Variable("method", cel.StringType),
		cel.Variable("userAgent", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("query", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("fp", cel.MapType(cel.StringType, cel.StringType)),
		// http.Header
		cel.Variable("headers", cel.MapType(cel.StringType, cel.StringType)),
		//TODO: dynamic type?
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

					network, ok := networks[val]
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

					network, ok := networks[val]
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
}

func Program(env *cel.Env, ast *cel.Ast) (cel.Program, error) {
	return env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
	)
}

func FromStrings(env *cel.Env, operator string, conditions ...string) (*cel.Ast, error) {
	var asts []*cel.Ast
	for _, c := range conditions {
		ast, issues := env.Compile(c)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("condition %s: %s", issues.Err(), c)
		}
		asts = append(asts, ast)
	}

	return Merge(env, operator, asts...)
}

func Merge(env *cel.Env, operator string, conditions ...*cel.Ast) (*cel.Ast, error) {
	if len(conditions) == 0 {
		return nil, nil
	} else if len(conditions) == 1 {
		return conditions[0], nil
	}
	var asts []string
	for _, c := range conditions {
		ast, err := cel.AstToString(c)
		if err != nil {
			return nil, err
		}
		asts = append(asts, "("+ast+")")
	}

	condition := strings.Join(asts, " "+operator+" ")
	ast, issues := env.Compile(condition)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	return ast, nil
}
