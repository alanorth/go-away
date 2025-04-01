package go_away

import (
	"codeberg.org/meta/gzipped/v2"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/google/cel-go/common/types"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

//go:embed assets
var assetsFs embed.FS

//go:embed challenge
var challengesFs embed.FS

//go:embed templates
var templatesFs embed.FS

var templates map[string]*template.Template

var cacheBust string

// DefaultValidity TODO: adjust
const DefaultValidity = time.Hour * 24 * 7

func init() {

	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	cacheBust = base64.RawURLEncoding.EncodeToString(buf)

	templates = make(map[string]*template.Template)

	dir, err := templatesFs.ReadDir("templates")
	if err != nil {
		panic(err)
	}
	for _, e := range dir {
		if e.IsDir() {
			continue
		}
		data, err := templatesFs.ReadFile(filepath.Join("templates", e.Name()))
		if err != nil {
			panic(err)
		}
		tpl := template.New(e.Name())
		_, err = tpl.Parse(string(data))
		if err != nil {
			panic(err)
		}
		templates[e.Name()] = tpl
	}
}

func (state *State) handleRequest(w http.ResponseWriter, r *http.Request) {

	//TODO better matcher! combo ast?
	env := map[string]any{
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

	for _, rule := range state.Rules {
	nextRule:
		if out, _, err := rule.Program.Eval(env); err != nil {
			//TODO error
			panic(err)
		} else if out != nil && out.Type() == types.BoolType {
			if out.Equal(types.True) == types.True {
				switch rule.Action {
				default:
					panic(fmt.Errorf("unknown action %s", rule.Action))
				case PolicyRuleActionPASS:
					state.Backend.ServeHTTP(w, r)
					return
				case PolicyRuleActionCHALLENGE, PolicyRuleActionCHECK:
					expiry := time.Now().UTC().Add(DefaultValidity).Round(DefaultValidity)

					for _, challengeName := range rule.Challenges {
						key := state.GetChallengeKeyForRequest(challengeName, expiry, r)
						ok, err := state.VerifyChallengeToken(challengeName, key, r)
						if !ok || err != nil {
							if !errors.Is(err, http.ErrNoCookie) {
								ClearCookie(CookiePrefix+challengeName, w)
							}
						} else {
							if rule.Action == PolicyRuleActionCHECK {
								goto nextRule
							}
							// we passed the challenge!
							//TODO log?
							state.Backend.ServeHTTP(w, r)
							return
						}
					}

					// none matched, issue first challenge in priority
					for _, challengeName := range rule.Challenges {
						c := state.Challenges[challengeName]
						if c.Challenge != nil {
							result := c.Challenge(w, r, state.GetChallengeKeyForRequest(challengeName, expiry, r), expiry)
							switch result {
							case ChallengeResultStop:
								return
							case ChallengeResultContinue:
								continue
							case ChallengeResultPass:
								if rule.Action == PolicyRuleActionCHECK {
									goto nextRule
								}
								// we pass the challenge early!
								state.Backend.ServeHTTP(w, r)
								return
							}
						} else {
							panic("challenge not found")
						}
					}
				case PolicyRuleActionDENY:
					//TODO: config error code
					http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
					return
				case PolicyRuleActionBLOCK:
					//TODO: config error code
					http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
					return
				}
			}
		}
	}

	state.Backend.ServeHTTP(w, r)
	return
}

func (state *State) setupRoutes() error {

	state.Mux.HandleFunc("/", state.handleRequest)

	state.Mux.Handle("GET "+state.UrlPath+"/assets/", http.StripPrefix(state.UrlPath, gzipped.FileServer(gzipped.FS(assetsFs))))

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

		if c.Verify != nil {
			state.Mux.HandleFunc(fmt.Sprintf("GET %s/verify-challenge", c.Path), func(w http.ResponseWriter, r *http.Request) {
				err := func() (err error) {
					expiry := time.Now().UTC().Add(DefaultValidity).Round(DefaultValidity)
					key := state.GetChallengeKeyForRequest(challengeName, expiry, r)
					result := r.FormValue("result")

					if ok, err := c.Verify(key, result); err != nil {
						return err
					} else if !ok {
						ClearCookie(CookiePrefix+challengeName, w)
						http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
						return nil
					}

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
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			})

		}
	}

	return nil
}

// UnixRoundTripper https://github.com/oauth2-proxy/oauth2-proxy/blob/master/pkg/upstream/http.go#L124
type UnixRoundTripper struct {
	Transport *http.Transport
}

// RoundTrip set bare minimum stuff
func (t UnixRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if req.Host == "" {
		req.Host = "localhost"
	}
	req.URL.Host = req.Host // proxy error: no Host in request URL
	req.URL.Scheme = "http" // make http.Transport happy and avoid an infinite recursion
	return t.Transport.RoundTrip(req)
}
