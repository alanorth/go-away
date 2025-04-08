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
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/google/cel-go/common/types"
	"html/template"
	"io"
	"log/slog"
	"maps"
	"net/http"
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
		_ = state.errorPage(w, id, http.StatusInternalServerError, err, "")
	} else {
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
	return nil
}

func (state *State) errorPage(w http.ResponseWriter, id string, status int, err error, redirect string) error {
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
		"Redirect":    redirect,
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

func GetLoggerForRequest(r *http.Request, clientHeader string) *slog.Logger {
	return slog.With(
		"request_id", r.Header.Get("X-Away-Id"),
		"remote_address", getRequestAddress(r, clientHeader),
		"user_agent", r.UserAgent(),
		"host", r.Host,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
	)
}

func (state *State) logger(r *http.Request) *slog.Logger {
	return GetLoggerForRequest(r, state.Settings.ClientIpHeader)
}

func (state *State) handleRequest(w http.ResponseWriter, r *http.Request) {
	host := r.Host

	data := RequestDataFromContext(r.Context())

	backend, ok := state.Settings.Backends[host]
	if !ok {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	lg := state.logger(r)

	start := time.Now()

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
		_ = state.errorPage(w, r.Header.Get("X-Away-Id"), code, err, "")
	}

	setAwayState := func(rule RuleState) {
		r.Header.Set("X-Away-Rule", rule.Name)
		r.Header.Set("X-Away-Hash", rule.Hash)
		r.Header.Set("X-Away-Action", string(rule.Action))
		data.Headers(state, r.Header)
	}

	for _, rule := range state.Rules {
		// skip rules that have host match
		if rule.Host != nil && *rule.Host != host {
			continue
		}
		start = time.Now()
		out, _, err := rule.Program.Eval(data.ProgramEnv)
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
					for _, challengeId := range rule.Challenges {
						if result := data.Challenges[challengeId]; !result.Ok() {
							continue
						} else {
							if rule.Action == policy.RuleActionCHECK {
								goto nextRule
							}

							// we passed the challenge!
							lg.Debug("request passed", "rule", rule.Name, "rule_hash", rule.Hash, "challenge", state.Challenges[challengeId].Name)
							setAwayState(rule)
							serve()
							return
						}
					}

					// none matched, issue first challenge in priority
					for _, challengeId := range rule.Challenges {
						result := data.Challenges[challengeId]
						if result.Ok() || result == challenge.VerifyResultSKIP {
							// skip already ok'd challenges for some reason, and also skip skipped challenges
							continue
						}
						c := state.Challenges[challengeId]
						if c.ServeChallenge != nil {
							result := c.ServeChallenge(w, r, state.GetChallengeKeyForRequest(c.Name, data.Expires, r), data.Expires)
							switch result {
							case challenge.ResultStop:
								lg.Info("request challenged", "rule", rule.Name, "rule_hash", rule.Hash, "challenge", c.Name)
								return
							case challenge.ResultContinue:
								continue
							case challenge.ResultPass:
								if rule.Action == policy.RuleActionCHECK {
									goto nextRule
								}
								state.logger(r).Warn("challenge passed", "rule", rule.Name, "rule_hash", rule.Hash, "challenge", c.Name)

								// set pass if caller didn't set one
								if !data.Challenges[c.Id].Ok() {
									data.Challenges[c.Id] = challenge.VerifyResultPASS
								}

								// we pass the challenge early!
								lg.Debug("request passed", "rule", rule.Name, "rule_hash", rule.Hash, "challenge", c.Name)
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

	for _, c := range state.Challenges {
		if c.ServeStatic != nil {
			state.Mux.Handle("GET "+c.Path+"/static/", c.ServeStatic)
		}

		if c.ServeScript != nil {
			state.Mux.Handle("GET "+c.ServeScriptPath, c.ServeScript)
		}

		if c.ServeMakeChallenge != nil {
			state.Mux.Handle(fmt.Sprintf("POST %s/make-challenge", c.Path), c.ServeMakeChallenge)
		}

		if c.ServeVerifyChallenge != nil {
			state.Mux.Handle(fmt.Sprintf("GET %s/verify-challenge", c.Path), c.ServeVerifyChallenge)
		} else if c.Verify != nil {
			state.Mux.HandleFunc(fmt.Sprintf("GET %s/verify-challenge", c.Path), func(w http.ResponseWriter, r *http.Request) {
				redirect, err := utils.EnsureNoOpenRedirect(r.FormValue("redirect"))
				if redirect == "" {
					_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusInternalServerError, err, "")
					return
				}

				err = func() (err error) {

					data := RequestDataFromContext(r.Context())

					key := state.GetChallengeKeyForRequest(c.Name, data.Expires, r)
					result := r.FormValue("result")

					requestId, err := hex.DecodeString(r.FormValue("requestId"))
					if err == nil {
						// override
						r.Header.Set("X-Away-Id", hex.EncodeToString(requestId))
					}

					start := time.Now()
					ok, err := c.Verify(key, result, r)
					state.addTiming(w, "challenge-verify", "Verify client challenge", time.Since(start))

					if err != nil {
						state.logger(r).Error(fmt.Errorf("challenge error: %w", err).Error(), "challenge", c.Name, "redirect", redirect)
						return err
					} else if !ok {
						state.logger(r).Warn("challenge failed", "challenge", c.Name, "redirect", redirect)
						utils.ClearCookie(utils.CookiePrefix+c.Name, w)
						_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusForbidden, fmt.Errorf("access denied: failed challenge %s", c.Name), redirect)
						return nil
					}
					state.logger(r).Info("challenge passed", "challenge", c.Name, "redirect", redirect)

					token, err := c.IssueChallengeToken(state.privateKey, key, []byte(result), data.Expires)
					if err != nil {
						utils.ClearCookie(utils.CookiePrefix+c.Name, w)
					} else {
						utils.SetCookie(utils.CookiePrefix+c.Name, token, data.Expires, w)
					}
					data.Challenges[c.Id] = challenge.VerifyResultPASS

					http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
					return nil
				}()
				if err != nil {
					utils.ClearCookie(utils.CookiePrefix+c.Name, w)
					_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusInternalServerError, err, redirect)
					return
				}
			})
		}
	}

	return nil
}

func (state *State) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var data RequestData
	// generate random id, todo: is this fast?
	_, _ = rand.Read(data.Id[:])
	data.Challenges = make(map[challenge.Id]challenge.VerifyResult, len(state.Challenges))
	data.Expires = time.Now().UTC().Add(DefaultValidity).Round(DefaultValidity)
	data.ProgramEnv = map[string]any{
		"host":          r.Host,
		"method":        r.Method,
		"remoteAddress": getRequestAddress(r, state.Settings.ClientIpHeader),
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

	for _, c := range state.Challenges {
		key := state.GetChallengeKeyForRequest(c.Name, data.Expires, r)
		result, err := c.VerifyChallengeToken(state.publicKey, key, r)
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			// clear invalid cookie
			utils.ClearCookie(utils.CookiePrefix+c.Name, w)
		}

		// prevent the challenge if not solved
		if !result.Ok() && c.Program != nil {
			out, _, err := c.Program.Eval(data.ProgramEnv)
			// verify eligibility
			if err != nil {
				state.logger(r).Error(err.Error(), "challenge", c.Name)
			} else if out != nil && out.Type() == types.BoolType {
				if out.Equal(types.True) != types.True {
					// skip challenge match!
					result = challenge.VerifyResultSKIP
					continue
				}
			}
		}
		data.Challenges[c.Id] = result
	}

	r.Header.Set("X-Away-Id", hex.EncodeToString(data.Id[:]))

	r = r.WithContext(context.WithValue(r.Context(), "_goaway_data", &data))

	state.Mux.ServeHTTP(w, r)
}

func RequestDataFromContext(ctx context.Context) *RequestData {
	return ctx.Value("_goaway_data").(*RequestData)
}

type RequestData struct {
	Id         [16]byte
	ProgramEnv map[string]any
	Expires    time.Time
	Challenges map[challenge.Id]challenge.VerifyResult
}

func (d *RequestData) HasValidChallenge(id challenge.Id) bool {
	return d.Challenges[id].Ok()
}

func (d *RequestData) Headers(state *State, headers http.Header) {
	for id, result := range d.Challenges {
		if result.Ok() {
			c, ok := state.Challenges[id]
			if !ok {
				panic("challenge not found")
			}

			headers.Set(fmt.Sprintf("X-Away-Challenge-%s-Result", c.Name), result.String())
		}
	}
}
