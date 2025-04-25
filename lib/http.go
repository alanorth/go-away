package lib

import (
	"codeberg.org/meta/gzipped/v2"
	"fmt"
	"git.gammaspectra.live/git/go-away/embed"
	"git.gammaspectra.live/git/go-away/lib/action"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/utils"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
)

var templates map[string]*template.Template

func init() {

	templates = make(map[string]*template.Template)

	dir, err := embed.TemplatesFs.ReadDir(".")
	if err != nil {
		panic(err)
	}
	for _, e := range dir {
		if e.IsDir() {
			continue
		}
		data, err := embed.TemplatesFs.ReadFile(e.Name())
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

func GetLoggerForRequest(r *http.Request) *slog.Logger {
	data := challenge.RequestDataFromContext(r.Context())
	args := []any{
		"request_id", data.Id.String(),
		"remote_address", data.RemoteAddress.Addr().String(),
		"user_agent", r.UserAgent(),
		"host", r.Host,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
	}

	if fp := utils.GetTLSFingerprint(r); fp != nil {
		if ja3n := fp.JA3N(); ja3n != nil {
			args = append(args, "ja3n", ja3n.String())
		}
		if ja4 := fp.JA4(); ja4 != nil {
			args = append(args, "ja4", ja4.String())
		}
	}
	return slog.With(args...)
}

func (state *State) handleRequest(w http.ResponseWriter, r *http.Request) {
	host := r.Host

	data := challenge.RequestDataFromContext(r.Context())

	backend := state.GetBackend(host)
	if backend == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	lg := state.Logger(r)

	cleanupRequest := func(r *http.Request, fromChallenge bool) {
		if fromChallenge {
			r.Header.Del("Referer")
		}
		q := r.URL.Query()

		if ref := q.Get(challenge.QueryArgReferer); ref != "" {
			r.Header.Set("Referer", ref)
		}

		// delete query parameters that were set by go-away
		for k := range q {
			if strings.HasPrefix(k, challenge.QueryArgPrefix) {
				q.Del(k)
			}
		}
		r.URL.RawQuery = q.Encode()

		data.Headers(r.Header)

		// delete cookies set by go-away to prevent user tracking that way
		cookies := r.Cookies()
		r.Header.Del("Cookie")
		for _, c := range cookies {
			if !strings.HasPrefix(c.Name, utils.CookiePrefix) {
				r.AddCookie(c)
			}
		}
	}

	for _, rule := range state.rules {
		next, err := rule.Evaluate(lg, w, r, func() http.Handler {
			cleanupRequest(r, true)
			return backend
		})
		if err != nil {
			state.ErrorPage(w, r, http.StatusInternalServerError, err, "")
			panic(err)
			return
		}

		if !next {
			return
		}
	}

	state.RuleHit(r, "DEFAULT", lg)

	// default pass
	_, _ = action.Pass{}.Handle(lg, w, r, func() http.Handler {
		r.Header.Set("X-Away-Rule", "DEFAULT")
		r.Header.Set("X-Away-Action", "PASS")

		cleanupRequest(r, false)
		return backend
	})
}

func (state *State) setupRoutes() error {

	state.Mux.HandleFunc("/", state.handleRequest)

	state.Mux.Handle("GET "+state.urlPath+"/assets/", http.StripPrefix(state.UrlPath()+"/assets/", gzipped.FileServer(gzipped.FS(embed.AssetsFs))))

	for _, reg := range state.challenges {

		if reg.Handler != nil {
			state.Mux.Handle(reg.Path+"/", reg.Handler)
		} else if reg.Verify != nil {
			// default verify
			state.Mux.HandleFunc(reg.Path+challenge.VerifyChallengeUrlSuffix, challenge.VerifyHandlerFunc(state, reg, nil, nil))
		}
	}

	return nil
}

func (state *State) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r, data := challenge.CreateRequestData(r, state)

	data.EvaluateChallenges(w, r)

	if state.Settings().MainName != "" {
		w.Header().Add("Via", fmt.Sprintf("%s %s@%s", r.Proto, state.Settings().MainName, state.Settings().MainVersion))
	}

	state.Mux.ServeHTTP(w, r)
}
