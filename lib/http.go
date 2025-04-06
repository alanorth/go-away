package lib

import (
	"bytes"
	"codeberg.org/meta/gzipped/v2"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/embed"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/google/cel-go/common/types"
	"html/template"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var templates map[string]*template.Template

var cacheBust string

// DefaultValidity TODO: adjust
const DefaultValidity = time.Hour * 24 * 7

func init() {

	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	cacheBust = base64.RawURLEncoding.EncodeToString(buf)

	templates = make(map[string]*template.Template)

	dir, err := embed.TemplatesFs.ReadDir("templates")
	if err != nil {
		panic(err)
	}
	for _, e := range dir {
		if e.IsDir() {
			continue
		}
		data, err := embed.TemplatesFs.ReadFile(filepath.Join("templates", e.Name()))
		if err != nil {
			panic(err)
		}
		err = initTemplate(e.Name(), string(data))
		if err != nil {
			panic(err)
		}
	}
}

func initTemplate(name, data string) error {
	tpl := template.New(name)
	_, err := tpl.Parse(data)
	if err != nil {
		return err
	}
	templates[name] = tpl
	return nil
}

func makeReverseProxy(target string) (*httputil.ReverseProxy, error) {
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
		transport.RegisterProtocol("unix", utils.UnixRoundTripper{Transport: transport})
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = transport

	return rp, nil
}

func (state *State) challengePage(w http.ResponseWriter, id string, status int, challenge string, params map[string]any) error {
	input := make(map[string]any)
	input["Id"] = id
	input["Random"] = cacheBust
	input["Challenge"] = challenge
	input["Path"] = state.UrlPath
	input["Theme"] = state.Settings.ChallengeTemplateTheme

	maps.Copy(input, params)

	if _, ok := input["Title"]; !ok {
		input["Title"] = "Checking you are not a bot"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	buf := bytes.NewBuffer(make([]byte, 0, 8192))

	err := templates["challenge-"+state.Settings.ChallengeTemplate+".gohtml"].Execute(buf, input)
	if err != nil {
		_ = state.errorPage(w, id, http.StatusInternalServerError, err)
	} else {
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
	return nil
}

func (state *State) errorPage(w http.ResponseWriter, id string, status int, err error) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	buf := bytes.NewBuffer(make([]byte, 0, 8192))

	err2 := templates["challenge-"+state.Settings.ChallengeTemplate+".gohtml"].Execute(buf, map[string]any{
		"Id":          id,
		"Random":      cacheBust,
		"Error":       err.Error(),
		"Path":        state.UrlPath,
		"Theme":       state.Settings.ChallengeTemplateTheme,
		"Title":       "Oh no! " + http.StatusText(status),
		"HideSpinner": true,
		"Challenge":   "",
	})
	if err2 != nil {
		panic(err2)
	} else {
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
	return nil
}

func (state *State) addTiming(w http.ResponseWriter, name, desc string, duration time.Duration) {
	if state.Settings.Debug {
		w.Header().Add("Server-Timing", fmt.Sprintf("%s;desc=%s;dur=%d", name, strconv.Quote(desc), duration.Milliseconds()))
	}
}

func (state *State) getLogger(r *http.Request) *slog.Logger {
	return slog.With(
		"request_id", r.Header.Get("X-Away-Id"),
		"remote_address", state.GetRequestAddress(r),
		"user_agent", r.UserAgent(),
		"host", r.Host,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
	)
}

func (state *State) handleRequest(w http.ResponseWriter, r *http.Request) {
	host := r.Host

	backend, ok := state.Backends[host]
	if !ok {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	lg := state.getLogger(r)

	start := time.Now()

	//TODO better matcher! combo ast?
	env := map[string]any{
		"host":          host,
		"method":        r.Method,
		"remoteAddress": state.GetRequestAddress(r),
		"userAgent":     r.UserAgent(),
		"path":          r.URL.Path,
		"query": func() map[string]string {
			result := make(map[string]string)
			for k, v := range r.URL.Query() {
				result[k] = strings.Join(v, ",")
			}
			return result
		}(),
		"headers": func() map[string]string {
			result := make(map[string]string)
			for k, v := range r.Header {
				result[k] = strings.Join(v, ",")
			}
			return result
		}(),
	}

	state.addTiming(w, "rule-env", "Setup the rule environment", time.Since(start))

	var (
		ruleEvalDuration time.Duration
	)

	serve := func() {
		state.addTiming(w, "rule-eval", "Evaluate access rules", ruleEvalDuration)
		backend.ServeHTTP(w, r)
	}

	fail := func(code int, err error) {
		state.addTiming(w, "rule-eval", "Evaluate access rules", ruleEvalDuration)
		_ = state.errorPage(w, r.Header.Get("X-Away-Id"), code, err)
	}

	setAwayState := func(rule RuleState) {
		r.Header.Set("X-Away-Rule", rule.Name)
		r.Header.Set("X-Away-Hash", rule.Hash)
		r.Header.Set("X-Away-Action", string(rule.Action))
	}

	for _, rule := range state.Rules {
		// skip rules that have host match
		if rule.Host != nil && *rule.Host != host {
			continue
		}
		start = time.Now()
		out, _, err := rule.Program.Eval(env)
		ruleEvalDuration += time.Since(start)

		if err != nil {
			fail(http.StatusInternalServerError, err)
			lg.Error(err.Error(), "rule", rule.Name, "rule_hash", rule.Hash)
			panic(err)
			return
		} else if out != nil && out.Type() == types.BoolType {
			if out.Equal(types.True) == types.True {
				switch rule.Action {
				default:
					panic(fmt.Errorf("unknown action %s", rule.Action))
				case policy.RuleActionPASS:
					lg.Debug("request passed", "rule", rule.Name, "rule_hash", rule.Hash)
					setAwayState(rule)
					serve()
					return
				case policy.RuleActionCHALLENGE, policy.RuleActionCHECK:
					start = time.Now()

					expiry := time.Now().UTC().Add(DefaultValidity).Round(DefaultValidity)

					for _, challengeName := range rule.Challenges {
						key := state.GetChallengeKeyForRequest(challengeName, expiry, r)
						ok, err := state.VerifyChallengeToken(challengeName, key, w, r)
						if !ok || err != nil {
							if !errors.Is(err, http.ErrNoCookie) {
								ClearCookie(CookiePrefix+challengeName, w)
							}
						} else {
							if rule.Action == policy.RuleActionCHECK {
								goto nextRule
							}
							// we passed the challenge!

							lg.Debug("request passed", "rule", rule.Name, "rule_hash", rule.Hash, "challenge", challengeName)
							setAwayState(rule)
							serve()
							return
						}
					}
					state.addTiming(w, "challenge-token-check", "Verify client challenge tokens", time.Since(start))

					// none matched, issue first challenge in priority
					for _, challengeName := range rule.Challenges {
						c := state.Challenges[challengeName]
						if c.Challenge != nil {
							result := c.Challenge(w, r, state.GetChallengeKeyForRequest(challengeName, expiry, r), expiry)
							switch result {
							case ChallengeResultStop:
								lg.Info("request challenged", "rule", rule.Name, "rule_hash", rule.Hash, "challenge", challengeName)
								return
							case ChallengeResultContinue:
								continue
							case ChallengeResultPass:
								if rule.Action == policy.RuleActionCHECK {
									goto nextRule
								}
								state.getLogger(r).Warn("challenge passed", "rule", rule.Name, "rule_hash", rule.Hash, "challenge", challengeName)

								// we pass the challenge early!
								r.Header.Set(fmt.Sprintf("X-Away-Challenge-%s-Verify", challengeName), "PASS")

								lg.Debug("request passed", "rule", rule.Name, "rule_hash", rule.Hash, "challenge", challengeName)
								setAwayState(rule)
								serve()
								return
							}
						} else {
							panic("challenge not found")
						}
					}
				case policy.RuleActionDENY:
					lg.Info("request denied", "rule", rule.Name, "rule_hash", rule.Hash)
					//TODO: config error code
					fail(http.StatusForbidden, fmt.Errorf("access denied: denied by administrative rule %s/%s", r.Header.Get("X-Away-Id"), rule.Hash))
					return
				case policy.RuleActionBLOCK:
					lg.Info("request blocked", "rule", rule.Name, "rule_hash", rule.Hash)
					//TODO: config error code
					//TODO: configure block
					fail(http.StatusForbidden, fmt.Errorf("access denied: blocked by administrative rule %s/%s", r.Header.Get("X-Away-Id"), rule.Hash))
					return
				case policy.RuleActionPOISON:
					lg.Info("request poisoned", "rule", rule.Name, "rule_hash", rule.Hash)

					mime := "text/html"
					switch path.Ext(r.URL.Path) {
					case ".css":
					case ".json", ".js", ".mjs":

					}

					encodings := strings.Split(r.Header.Get("Accept-Encoding"), ",")
					for i, encoding := range encodings {
						encodings[i] = strings.TrimSpace(strings.ToLower(encoding))
					}

					reader, encoding := state.getPoison(mime, encodings)
					if reader == nil {
						mime = "application/octet-stream"
						reader, encoding = state.getPoison(mime, encodings)
					}

					if reader != nil {
						defer reader.Close()
					}

					w.Header().Set("Cache-Control", "max-age=0, private, must-revalidate, no-transform")
					w.Header().Set("Vary", "Accept-Encoding")
					w.Header().Set("Content-Type", mime)
					w.Header().Set("X-Content-Type-Options", "nosniff")
					if encoding != "" {
						w.Header().Set("Content-Encoding", encoding)
					}
					w.WriteHeader(http.StatusOK)
					if flusher, ok := w.(http.Flusher); ok {
						// trigger chunked encoding
						flusher.Flush()
					}
					if r != nil {
						_, _ = io.Copy(w, reader)
					}
					return
				}
			}
		}

	nextRule:
	}

	serve()
	return
}

func (state *State) setupRoutes() error {

	state.Mux.HandleFunc("/", state.handleRequest)

	state.Mux.Handle("GET "+state.UrlPath+"/assets/", http.StripPrefix(state.UrlPath, gzipped.FileServer(gzipped.FS(embed.AssetsFs))))

	for challengeName, c := range state.Challenges {
		if c.Static != nil {
			state.Mux.Handle("GET "+c.Path+"/static/", c.Static)
		}

		if c.ChallengeScript != nil {
			state.Mux.Handle("GET "+c.ChallengeScriptPath, c.ChallengeScript)
		}

		if c.MakeChallenge != nil {
			state.Mux.Handle(fmt.Sprintf("POST %s/make-challenge", c.Path), c.MakeChallenge)
		}

		if c.VerifyChallenge != nil {
			state.Mux.Handle(fmt.Sprintf("GET %s/verify-challenge", c.Path), c.VerifyChallenge)
		} else if c.Verify != nil {
			state.Mux.HandleFunc(fmt.Sprintf("GET %s/verify-challenge", c.Path), func(w http.ResponseWriter, r *http.Request) {
				err := func() (err error) {
					expiry := time.Now().UTC().Add(DefaultValidity).Round(DefaultValidity)
					key := state.GetChallengeKeyForRequest(challengeName, expiry, r)
					result := r.FormValue("result")

					requestId, err := hex.DecodeString(r.FormValue("requestId"))
					if err == nil {
						r.Header.Set("X-Away-Id", hex.EncodeToString(requestId))
					}

					start := time.Now()
					ok, err := c.Verify(key, result)
					state.addTiming(w, "challenge-verify", "Verify client challenge", time.Since(start))

					if err != nil {
						state.getLogger(r).Error(fmt.Errorf("challenge error: %w", err).Error(), "challenge", challengeName, "redirect", r.FormValue("redirect"))
						return err
					} else if !ok {
						state.getLogger(r).Warn("challenge failed", "challenge", challengeName, "redirect", r.FormValue("redirect"))
						ClearCookie(CookiePrefix+challengeName, w)
						_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusForbidden, fmt.Errorf("access denied: failed challenge %s", challengeName))
						return nil
					}
					state.getLogger(r).Info("challenge passed", "challenge", challengeName, "redirect", r.FormValue("redirect"))

					token, err := state.IssueChallengeToken(challengeName, key, []byte(result), expiry)
					if err != nil {
						ClearCookie(CookiePrefix+challengeName, w)
					} else {
						SetCookie(CookiePrefix+challengeName, token, expiry, w)
					}

					http.Redirect(w, r, r.FormValue("redirect"), http.StatusTemporaryRedirect)
					return nil
				}()
				if err != nil {
					ClearCookie(CookiePrefix+challengeName, w)
					_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusInternalServerError, err)
					return
				}
			})
		}
	}

	return nil
}
