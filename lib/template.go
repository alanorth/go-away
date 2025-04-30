package lib

import (
	"bytes"
	"git.gammaspectra.live/git/go-away/embed"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/utils"
	"html/template"
	"maps"
	"net/http"
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
	tpl := template.New(name).Funcs(template.FuncMap{
		"attr": func(s string) template.HTMLAttr {
			return template.HTMLAttr(s)
		},
		"safe": func(s string) template.HTML {
			return template.HTML(s)
		},
	})
	_, err := tpl.Parse(data)
	if err != nil {
		return err
	}
	templates[name] = tpl
	return nil
}

func (state *State) ChallengePage(w http.ResponseWriter, r *http.Request, status int, reg *challenge.Registration, params map[string]any) {
	data := challenge.RequestDataFromContext(r.Context())
	input := make(map[string]any)
	input["Id"] = data.Id.String()
	input["Random"] = utils.CacheBust()

	input["Path"] = state.UrlPath()
	input["Links"] = state.opt.Links
	input["Strings"] = state.opt.Strings
	for k, v := range state.opt.ChallengeTemplateOverrides {
		input[k] = v
	}

	if reg != nil {
		input["Challenge"] = reg.Name
	}

	maps.Copy(input, params)

	if _, ok := input["Title"]; !ok {
		input["Title"] = state.opt.Strings.Get("title_challenge")
	}

	if data.GetOptBool(challenge.RequestOptCacheMetaTags, false) {
		backend, host := data.BackendHost()
		if tags := state.fetchMetaTags(host, backend, r); len(tags) > 0 {
			tagMap, _ := input["Meta"].([]map[string]string)

			for _, tag := range tags {
				tagAttrs := make(map[string]string, len(tag.Attr))
				for _, v := range tag.Attr {
					tagAttrs[v.Key] = v.Val
				}
				tagMap = append(tagMap, tagAttrs)
			}
			input["Meta"] = tagMap
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	buf := bytes.NewBuffer(make([]byte, 0, 8192))

	err := templates["challenge-"+state.opt.ChallengeTemplate+".gohtml"].Execute(buf, input)
	if err != nil {
		state.ErrorPage(w, r, http.StatusInternalServerError, err, "")
	} else {
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
}

func (state *State) ErrorPage(w http.ResponseWriter, r *http.Request, status int, err error, redirect string) {
	data := challenge.RequestDataFromContext(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	buf := bytes.NewBuffer(make([]byte, 0, 8192))

	input := map[string]any{
		"Id":        data.Id.String(),
		"Random":    utils.CacheBust(),
		"Error":     err.Error(),
		"Path":      state.UrlPath(),
		"Theme":     "",
		"Title":     template.HTML(string(state.opt.Strings.Get("title_error")) + " " + http.StatusText(status)),
		"Challenge": "",
		"Redirect":  redirect,
		"Links":     state.opt.Links,
		"Strings":   state.opt.Strings,
	}
	for k, v := range state.opt.ChallengeTemplateOverrides {
		input[k] = v
	}

	if data.GetOptBool(challenge.RequestOptCacheMetaTags, false) {
		backend, host := data.BackendHost()
		if tags := state.fetchMetaTags(host, backend, r); len(tags) > 0 {
			tagMap, _ := input["Meta"].([]map[string]string)

			for _, tag := range tags {
				tagAttrs := make(map[string]string, len(tag.Attr))
				for _, v := range tag.Attr {
					tagAttrs[v.Key] = v.Val
				}
				tagMap = append(tagMap, tagAttrs)
			}
			input["Meta"] = tagMap
		}
	}

	err2 := templates["challenge-"+state.opt.ChallengeTemplate+".gohtml"].Execute(buf, input)
	if err2 != nil {
		// nested errors!
		panic(err2)
	} else {
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
}
