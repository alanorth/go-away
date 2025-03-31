package go_away

import (
	"codeberg.org/meta/gzipped/v2"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/challenge"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/yl2chen/cidranger"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type State struct {
	Client      *http.Client
	PackagePath string
	UrlPath     string
	Mux         *http.ServeMux
	Backend     http.Handler

	Networks map[string]cidranger.Ranger

	UserAgents map[string][]*regexp.Regexp

	WasmRuntime wazero.Runtime
	WasmContext context.Context

	Challenges map[string]ChallengeState

	RulesEnv   *cel.Env
	Conditions map[string]*cel.Ast

	Rules []RuleState

	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

type RuleState struct {
	Name string

	Program    cel.Program
	Action     PolicyRuleAction
	Challenges []string
}

type ChallengeResult int

const (
	// ChallengeResultStop Stop testing challenges and return
	ChallengeResultStop = ChallengeResult(iota)
	// ChallengeResultContinue Test next challenge
	ChallengeResultContinue
	// ChallengeResultPass Challenge passed, return and proxy
	ChallengeResultPass
)

type ChallengeState struct {
	RuntimeModule wazero.CompiledModule

	Path string

	Static              http.Handler
	Challenge           func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) ChallengeResult
	ChallengeScriptPath string
	ChallengeScript     http.Handler
	MakeChallenge       http.Handler
	VerifyChallenge     http.Handler

	VerifyProbability float64
	Verify            func(key []byte, result string) (bool, error)
}

func NewState(policy Policy, packagePath string, backend http.Handler) (state *State, err error) {
	state = new(State)
	state.Client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	state.PackagePath = packagePath
	state.UrlPath = "/.well-known/." + state.PackagePath
	state.Backend = backend

	state.UserAgents = make(map[string][]*regexp.Regexp)
	for k, v := range policy.UserAgents {
		for _, str := range v {
			expr, err := regexp.Compile(str)
			if err != nil {
				return nil, fmt.Errorf("user-agent %s: invalid regex expression %s: %v", k, str, err)
			}
			state.UserAgents[k] = append(state.UserAgents[k], expr)
		}
	}
	state.Networks = make(map[string]cidranger.Ranger)
	for k, network := range policy.Networks {
		ranger := cidranger.NewPCTrieRanger()
		for _, e := range network {
			prefixes, err := e.FetchPrefixes()
			if err != nil {
				return nil, fmt.Errorf("networks %s: error fetching prefixes: %v", k, err)
			}
			for _, prefix := range prefixes {
				err = ranger.Insert(cidranger.NewBasicRangerEntry(prefix))
				if err != nil {
					return nil, fmt.Errorf("networks %s: error inserting prefix %s: %v", k, prefix.String(), err)
				}
			}
		}

		state.Networks[k] = ranger
	}

	state.WasmContext = context.Background()
	state.WasmRuntime = wazero.NewRuntimeWithConfig(state.WasmContext, wazero.NewRuntimeConfigCompiler())
	wasi_snapshot_preview1.MustInstantiate(state.WasmContext, state.WasmRuntime)

	state.Challenges = make(map[string]ChallengeState)

	for challengeName, p := range policy.Challenges {
		c := ChallengeState{
			Path:              fmt.Sprintf("%s/challenge/%s", state.UrlPath, challengeName),
			VerifyProbability: p.Runtime.Probability,
		}

		if c.VerifyProbability <= 0 {
			//10% default
			c.VerifyProbability = 0.1
		} else if c.VerifyProbability > 1.0 {
			c.VerifyProbability = 1.0
		}

		assetPath := c.Path + "/static/"
		subFs, err := fs.Sub(challengesFs, fmt.Sprintf("challenge/%s/static", challengeName))
		if err == nil {
			c.Static = http.StripPrefix(
				assetPath,
				gzipped.FileServer(gzipped.FS(subFs)),
			)
		}

		switch p.Mode {
		default:
			return nil, fmt.Errorf("unknown challenge mode: %s", p.Mode)
		case "http":
			if p.Url == nil {
				return nil, fmt.Errorf("challenge %s: missing url", challengeName)
			}
			method := p.Parameters["http-method"]
			if method == "" {
				method = "GET"
			}

			httpCode, _ := strconv.Atoi(p.Parameters["http-code"])
			if httpCode == 0 {
				httpCode = http.StatusOK
			}

			//todo
			c.Challenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) ChallengeResult {
				request, err := http.NewRequest(method, *p.Url, nil)
				if err != nil {
					return ChallengeResultContinue
				}

				request.Header = r.Header
				response, err := state.Client.Do(request)
				if err != nil {
					return ChallengeResultContinue
				}
				defer response.Body.Close()
				defer io.Copy(io.Discard, response.Body)

				if response.StatusCode != httpCode {
					ClearCookie(CookiePrefix+challengeName, w)
					// continue other challenges!
					return ChallengeResultContinue
				} else {
					token, err := state.IssueChallengeToken(challengeName, key, nil, expiry)
					if err != nil {
						ClearCookie(CookiePrefix+challengeName, w)
					} else {
						SetCookie(CookiePrefix+challengeName, token, expiry, w)
					}

					// we passed it!
					return ChallengeResultPass
				}
			}

		case "cookie":
			c.Challenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) ChallengeResult {
				token, err := state.IssueChallengeToken(challengeName, key, nil, expiry)
				if err != nil {
					ClearCookie(CookiePrefix+challengeName, w)
				} else {
					SetCookie(CookiePrefix+challengeName, token, expiry, w)
				}
				// self redirect!
				//TODO: add redirect loop detect parameter
				http.Redirect(w, r, r.URL.String(), http.StatusTemporaryRedirect)
				return ChallengeResultStop
			}
		case "meta-refresh":
			c.Challenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) ChallengeResult {
				redirectUri := new(url.URL)
				redirectUri.Path = c.Path + "/verify-challenge"

				values := make(url.Values)
				values.Set("result", hex.EncodeToString(key))
				values.Set("redirect", r.URL.String())

				redirectUri.RawQuery = values.Encode()

				// self redirect!
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusTeapot)

				_ = templates["challenge.gohtml"].Execute(w, map[string]any{
					"Title":     "Bot",
					"Path":      state.UrlPath,
					"Random":    cacheBust,
					"Challenge": "",
					"Meta": map[string]string{
						"refresh": "0; url=" + redirectUri.String(),
					},
				})
				return ChallengeResultStop
			}
		case "header-refresh":
			c.Challenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) ChallengeResult {
				redirectUri := new(url.URL)
				redirectUri.Path = c.Path + "/verify-challenge"

				values := make(url.Values)
				values.Set("result", hex.EncodeToString(key))
				values.Set("redirect", r.URL.String())

				redirectUri.RawQuery = values.Encode()

				// self redirect!
				w.Header().Set("Refresh", "0; url="+redirectUri.String())
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusTeapot)

				_ = templates["challenge.gohtml"].Execute(w, map[string]any{
					"Title":     "Bot",
					"Path":      state.UrlPath,
					"Random":    cacheBust,
					"Challenge": "",
				})
				return ChallengeResultStop
			}
		case "js":
			c.Challenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) ChallengeResult {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusTeapot)

				err := templates["challenge.gohtml"].Execute(w, map[string]any{
					"Title":     "Bot",
					"Path":      state.UrlPath,
					"Random":    cacheBust,
					"Challenge": challengeName,
				})
				if err != nil {
					//TODO: log
				}
				return ChallengeResultStop
			}
			c.ChallengeScriptPath = c.Path + "/challenge.mjs"
			c.ChallengeScript = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
				w.WriteHeader(http.StatusOK)

				params, _ := json.Marshal(p.Parameters)

				err := templates["challenge.mjs"].Execute(w, map[string]any{
					"Path":       c.Path,
					"Parameters": string(params),
					"Random":     cacheBust,
					"Challenge":  challengeName,
					"ChallengeScript": func() string {
						if p.Asset != nil {
							return assetPath + *p.Asset
						} else if p.Url != nil {
							return *p.Url
						} else {
							panic("not implemented")
						}
					}(),
				})
				if err != nil {
					//TODO: log
				}
			})
		}

		// how to runtime
		switch p.Runtime.Mode {
		default:
			return nil, fmt.Errorf("unknown challenge runtime mode: %s", p.Runtime.Mode)
		case "":
		case "http":
		case "key":
			c.Verify = func(key []byte, result string) (bool, error) {
				resultBytes, err := hex.DecodeString(result)
				if err != nil {
					return false, err
				}

				if subtle.ConstantTimeCompare(resultBytes, key) != 1 {
					return false, nil
				}
				return true, nil
			}

		case "wasm":
			wasmData, err := challengesFs.ReadFile(fmt.Sprintf("challenge/%s/runtime/%s", challengeName, p.Runtime.Asset))
			if err != nil {
				return nil, fmt.Errorf("c %s: could not load runtime: %w", challengeName, err)
			}
			c.RuntimeModule, err = state.WasmRuntime.CompileModule(state.WasmContext, wasmData)
			if err != nil {
				return nil, fmt.Errorf("c %s: compiling runtime: %w", challengeName, err)
			}

			c.MakeChallenge = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := state.ChallengeMod(challengeName, func(ctx context.Context, mod api.Module) (err error) {

					in := challenge.MakeChallengeInput{
						Key:        state.GetChallengeKeyForRequest(challengeName, time.Now().UTC().Add(DefaultValidity).Round(DefaultValidity), r),
						Parameters: p.Parameters,
						Headers:    r.Header,
					}
					in.Data, err = io.ReadAll(r.Body)
					if err != nil {
						return err
					}

					out, err := challenge.MakeChallengeCall(state.WasmContext, mod, in)
					if err != nil {
						return err
					}

					// set output headers
					for k, v := range out.Headers {
						w.Header()[k] = v
					}
					w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out.Data)))
					w.WriteHeader(out.Code)
					_, _ = w.Write(out.Data)
					return nil
				})
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			})

			c.Verify = func(key []byte, result string) (ok bool, err error) {
				err = state.ChallengeMod(challengeName, func(ctx context.Context, mod api.Module) (err error) {
					in := challenge.VerifyChallengeInput{
						Key:        key,
						Parameters: p.Parameters,
						Result:     []byte(result),
					}

					out, err := challenge.VerifyChallengeCall(state.WasmContext, mod, in)
					if err != nil {
						return err
					}

					if out == challenge.VerifyChallengeOutputError {
						return errors.New("error checking challenge")
					}
					ok = out == challenge.VerifyChallengeOutputOK
					return nil
				})
				if err != nil {
					return false, err
				}
				return ok, nil
			}
		}

		state.Challenges[challengeName] = c
	}

	state.RulesEnv, err = cel.NewEnv(
		cel.DefaultUTCTimeZone(true),
		cel.Variable("remoteAddress", cel.BytesType),
		cel.Variable("userAgent", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("query", cel.MapType(cel.StringType, cel.StringType)),
		// http.Header
		cel.Variable("headers", cel.MapType(cel.StringType, cel.StringType)),
		//TODO: dynamic type?
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
		return nil, err
	}

	state.Conditions = make(map[string]*cel.Ast)
	for k, entries := range policy.Conditions {
		ast, err := ConditionFromStrings(state.RulesEnv, OperatorOr, entries...)
		if err != nil {
			return nil, fmt.Errorf("conditions %s: error compiling conditions: %v", k, err)
		}
		state.Conditions[k] = ast
	}

	for _, rule := range policy.Rules {
		r := RuleState{
			Name:       rule.Name,
			Action:     PolicyRuleAction(strings.ToUpper(rule.Action)),
			Challenges: rule.Challenges,
		}

		if r.Action == PolicyRuleActionCHALLENGE && len(r.Challenges) == 0 {
			return nil, fmt.Errorf("no challenges found in rule %s", rule.Name)
		}

		//TODO: nesting conditions via decorator!
		ast, err := ConditionFromStrings(state.RulesEnv, OperatorOr, rule.Conditions...)
		if err != nil {
			return nil, fmt.Errorf("rules %s: error compiling conditions: %v", rule.Name, err)
		}
		program, err := state.RulesEnv.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("rules %s: error compiling program: %v", rule.Name, err)
		}
		r.Program = program

		state.Rules = append(state.Rules, r)
	}

	state.Mux = http.NewServeMux()

	state.PublicKey, state.PrivateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	if err = state.setupRoutes(); err != nil {
		return nil, err
	}

	return state, nil
}

func (state *State) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state.Mux.ServeHTTP(w, r)
}
