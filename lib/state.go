package lib

import (
	"codeberg.org/meta/gzipped/v2"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	go_away "git.gammaspectra.live/git/go-away"
	"git.gammaspectra.live/git/go-away/challenge"
	"git.gammaspectra.live/git/go-away/challenge/inline"
	"git.gammaspectra.live/git/go-away/lib/condition"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/yl2chen/cidranger"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type State struct {
	Client   *http.Client
	Settings StateSettings
	UrlPath  string
	Mux      *http.ServeMux
	Backends map[string]http.Handler

	Networks map[string]cidranger.Ranger

	WasmRuntime wazero.Runtime
	WasmContext context.Context

	Challenges map[string]ChallengeState

	RulesEnv *cel.Env

	Rules []RuleState

	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

type RuleState struct {
	Name string
	Hash string

	Host *string

	Program    cel.Program
	Action     policy.RuleAction
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
	Verify              func(key []byte, result string) (bool, error)

	VerifyProbability float64
}

type StateSettings struct {
	PackagePath            string
	ChallengeTemplate      string
	ChallengeTemplateTheme string
}

func NewState(p policy.Policy, settings StateSettings) (state *State, err error) {
	state = new(State)
	state.Settings = settings
	state.Client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	state.UrlPath = "/.well-known/." + state.Settings.PackagePath

	state.Backends = make(map[string]http.Handler)

	for k, v := range p.Backends {
		backend, err := makeReverseProxy(v)
		if err != nil {
			return nil, fmt.Errorf("backend %s: failed to make reverse proxy: %w", k, err)
		}
		state.Backends[k] = backend
	}

	state.PublicKey, state.PrivateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	privateKeyFingerprint := sha256.Sum256(state.PrivateKey)

	if state.Settings.ChallengeTemplate == "" {
		state.Settings.ChallengeTemplate = "anubis"
	}

	if templates["challenge-"+state.Settings.ChallengeTemplate+".gohtml"] == nil {

		if data, err := os.ReadFile(state.Settings.ChallengeTemplate); err == nil && len(data) > 0 {
			name := path.Base(state.Settings.ChallengeTemplate)
			err := initTemplate(name, string(data))
			if err != nil {
				return nil, fmt.Errorf("error loading template %s: %w", settings.ChallengeTemplate, err)
			}
			state.Settings.ChallengeTemplate = name
		}

		return nil, fmt.Errorf("no template defined for %s", settings.ChallengeTemplate)
	}

	state.Networks = make(map[string]cidranger.Ranger)
	for k, network := range p.Networks {
		ranger := cidranger.NewPCTrieRanger()
		for _, e := range network {
			if e.Url != nil {
				slog.Debug("loading network url list", "network", k, "url", *e.Url)
			}
			prefixes, err := e.FetchPrefixes(state.Client)
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

		slog.Debug("loaded network prefixes", "network", k, "count", ranger.Len())

		state.Networks[k] = ranger
	}

	state.WasmContext = context.Background()
	state.WasmRuntime = wazero.NewRuntimeWithConfig(state.WasmContext, wazero.NewRuntimeConfigCompiler())
	wasi_snapshot_preview1.MustInstantiate(state.WasmContext, state.WasmRuntime)

	state.Challenges = make(map[string]ChallengeState)

	for challengeName, p := range p.Challenges {
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
		subFs, err := fs.Sub(go_away.ChallengeFs, fmt.Sprintf("challenge/%s/static", challengeName))
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

			expectedCookie := p.Parameters["http-cookie"]

			//todo
			c.Challenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) ChallengeResult {
				if expectedCookie != "" {
					if cookie, err := r.Cookie(expectedCookie); err != nil || cookie == nil {
						// skip check if we don't have cookie or it's expired
						return ChallengeResultContinue
					}
				}

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

				_ = state.challengePage(w, http.StatusTeapot, "", map[string]any{
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

				_ = state.challengePage(w, http.StatusTeapot, "", nil)

				return ChallengeResultStop
			}
		case "resource-load":
			c.Challenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) ChallengeResult {
				redirectUri := new(url.URL)
				redirectUri.Path = c.Path + "/verify-challenge"

				values := make(url.Values)
				values.Set("result", hex.EncodeToString(key))

				redirectUri.RawQuery = values.Encode()

				// self redirect!
				w.Header().Set("Refresh", "2; url="+r.URL.String())

				_ = state.challengePage(w, http.StatusTeapot, "", map[string]any{
					"Tags": []template.HTML{
						template.HTML(fmt.Sprintf("<link href=\"%s\" rel=\"stylesheet\" crossorigin=\"use-credentials\">", redirectUri.String())),
					},
				})

				return ChallengeResultStop
			}
		case "js":
			c.Challenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) ChallengeResult {
				_ = state.challengePage(w, http.StatusTeapot, challengeName, nil)

				return ChallengeResultStop
			}
			c.ChallengeScriptPath = c.Path + "/challenge.mjs"
			c.ChallengeScript = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				params, _ := json.Marshal(p.Parameters)

				//TODO: move this to http.go as a template
				w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
				w.WriteHeader(http.StatusOK)

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
			mimeType := p.Parameters["key-mime"]
			if mimeType == "" {
				mimeType = "text/html; charset=utf-8"
			}

			httpCode, _ := strconv.Atoi(p.Parameters["key-code"])
			if httpCode == 0 {
				httpCode = http.StatusTemporaryRedirect
			}

			var content []byte
			if data, ok := p.Parameters["key-content"]; ok {
				content = []byte(data)
			}

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

			c.VerifyChallenge = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				err := func() (err error) {
					expiry := time.Now().UTC().Add(DefaultValidity).Round(DefaultValidity)

					key := state.GetChallengeKeyForRequest(challengeName, expiry, r)
					result := r.FormValue("result")

					if ok, err := c.Verify(key, result); err != nil {
						return err
					} else if !ok {
						ClearCookie(CookiePrefix+challengeName, w)
						_ = state.errorPage(w, http.StatusForbidden, fmt.Errorf("access denied: failed challenge %s", challengeName))
						return nil
					}

					token, err := state.IssueChallengeToken(challengeName, key, []byte(result), expiry)
					if err != nil {
						ClearCookie(CookiePrefix+challengeName, w)
					} else {
						SetCookie(CookiePrefix+challengeName, token, expiry, w)
					}

					switch httpCode {
					case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
						http.Redirect(w, r, r.FormValue("redirect"), httpCode)
					default:
						w.Header().Set("Content-Type", mimeType)
						w.WriteHeader(httpCode)
						if content != nil {
							_, _ = w.Write(content)
						}
					}

					return nil
				}()
				if err != nil {
					ClearCookie(CookiePrefix+challengeName, w)
					_ = state.errorPage(w, http.StatusInternalServerError, err)
					return
				}
			})

		case "wasm":
			wasmData, err := go_away.ChallengeFs.ReadFile(fmt.Sprintf("challenge/%s/runtime/%s", challengeName, p.Runtime.Asset))
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
						Headers:    inline.MIMEHeader(r.Header),
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
					_ = state.errorPage(w, http.StatusInternalServerError, err)
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
		cel.Variable("host", cel.StringType),
		cel.Variable("method", cel.StringType),
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

	var replacements []string
	for k, entries := range p.Conditions {
		ast, err := condition.FromStrings(state.RulesEnv, condition.OperatorOr, entries...)
		if err != nil {
			return nil, fmt.Errorf("conditions %s: error compiling conditions: %v", k, err)
		}

		cond, err := cel.AstToString(ast)
		if err != nil {
			return nil, fmt.Errorf("conditions %s: error printing condition: %v", k, err)
		}

		replacements = append(replacements, fmt.Sprintf("($%s)", k))
		replacements = append(replacements, "("+cond+")")
	}
	conditionReplacer := strings.NewReplacer(replacements...)

	for _, rule := range p.Rules {
		hasher := sha256.New()
		hasher.Write([]byte(rule.Name))
		hasher.Write([]byte{0})
		if rule.Host != nil {
			hasher.Write([]byte(*rule.Host))
		}
		hasher.Write([]byte{0})
		hasher.Write(privateKeyFingerprint[:])
		sum := hasher.Sum(nil)

		r := RuleState{
			Name:       rule.Name,
			Hash:       hex.EncodeToString(sum[:8]),
			Host:       rule.Host,
			Action:     policy.RuleAction(strings.ToUpper(rule.Action)),
			Challenges: rule.Challenges,
		}

		if (r.Action == policy.RuleActionCHALLENGE || r.Action == policy.RuleActionCHECK) && len(r.Challenges) == 0 {
			return nil, fmt.Errorf("no challenges found in rule %s", rule.Name)
		}

		// allow nesting
		var conditions []string
		for _, cond := range rule.Conditions {
			cond = conditionReplacer.Replace(cond)
			conditions = append(conditions, cond)
		}

		ast, err := condition.FromStrings(state.RulesEnv, condition.OperatorOr, conditions...)
		if err != nil {
			return nil, fmt.Errorf("rules %s: error compiling conditions: %v", rule.Name, err)
		}
		program, err := state.RulesEnv.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("rules %s: error compiling program: %v", rule.Name, err)
		}
		r.Program = program

		slog.Info("loaded rule", "rule", r.Name, "hash", r.Hash, "action", rule.Action)

		state.Rules = append(state.Rules, r)
	}

	state.Mux = http.NewServeMux()

	if err = state.setupRoutes(); err != nil {
		return nil, err
	}

	return state, nil
}

func (state *State) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state.Mux.ServeHTTP(w, r)
}
