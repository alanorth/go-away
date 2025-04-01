package lib

import (
	"codeberg.org/meta/gzipped/v2"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	go_away "git.gammaspectra.live/git/go-away"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/google/cel-go/common/types"
	"html/template"
	"net/http"
	"path/filepath"
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

	dir, err := go_away.TemplatesFs.ReadDir("templates")
	if err != nil {
		panic(err)
	}
	for _, e := range dir {
		if e.IsDir() {
			continue
		}
		data, err := go_away.TemplatesFs.ReadFile(filepath.Join("templates", e.Name()))
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
		if out, _, err := rule.Program.Eval(env); err != nil {
			//TODO error
			panic(err)
		} else if out != nil && out.Type() == types.BoolType {
			if out.Equal(types.True) == types.True {
				switch rule.Action {
				default:
					panic(fmt.Errorf("unknown action %s", rule.Action))
				case policy.RuleActionPASS:
					state.Backend.ServeHTTP(w, r)
					return
				case policy.RuleActionCHALLENGE, policy.RuleActionCHECK:
					expiry := time.Now().UTC().Add(DefaultValidity).Round(DefaultValidity)

					for _, challengeName := range rule.Challenges {
						key := state.GetChallengeKeyForRequest(challengeName, expiry, r)
						ok, err := state.VerifyChallengeToken(challengeName, key, r)
						if !ok || err != nil {
							if !errors.Is(err, http.ErrNoCookie) {
								ClearCookie(CookiePrefix+challengeName, w)
							}
						} else {
							if rule.Action == policy.RuleActionCHECK {
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
								if rule.Action == policy.RuleActionCHECK {
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
				case policy.RuleActionDENY:
					//TODO: config error code
					http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
					return
				case policy.RuleActionBLOCK:
					//TODO: config error code
					http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
					return
				}
			}
		}

	nextRule:
	}

	state.Backend.ServeHTTP(w, r)
	return
}

func (state *State) setupRoutes() error {

	state.Mux.HandleFunc("/", state.handleRequest)

	state.Mux.Handle("GET "+state.UrlPath+"/assets/", http.StripPrefix(state.UrlPath, gzipped.FileServer(gzipped.FS(go_away.AssetsFs))))

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
