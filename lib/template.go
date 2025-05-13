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

func (state *State) addCachedTags(data *challenge.RequestData, r *http.Request, input map[string]any) {
	proxyMetaTags := data.GetOptBool(challenge.RequestOptProxyMetaTags, false)
	proxySafeLinkTags := data.GetOptBool(challenge.RequestOptProxySafeLinkTags, false)
	if proxyMetaTags || proxySafeLinkTags {
		backend, host := data.BackendHost()
		if tags := state.fetchTags(host, backend, r, proxyMetaTags, proxySafeLinkTags); len(tags) > 0 {
			metaTagMap, _ := input["MetaTags"].([]map[string]string)
			linkTagMap, _ := input["LinkTags"].([]map[string]string)

			for _, tag := range tags {
				tagAttrs := make(map[string]string, len(tag.Attr))
				for _, v := range tag.Attr {
					tagAttrs[v.Key] = v.Val
				}
				metaTagMap = append(metaTagMap, tagAttrs)
			}
			input["MetaTags"] = metaTagMap
			input["LinkTags"] = linkTagMap
		}
	}
}

func (state *State) ChallengePage(w http.ResponseWriter, r *http.Request, status int, reg *challenge.Registration, params map[string]any) {
	data := challenge.RequestDataFromContext(r.Context())
	input := make(map[string]any)
	input["Id"] = data.Id.String()
	input["Random"] = utils.StaticCacheBust()

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

	state.addCachedTags(data, r, input)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	buf := bytes.NewBuffer(make([]byte, 0, 8192))

	err := templates["challenge-"+state.opt.ChallengeTemplate+".gohtml"].Execute(buf, input)
	if err != nil {
		state.ErrorPage(w, r, http.StatusInternalServerError, err, "")
	} else {
		data.ResponseHeaders(w)
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
		"Random":    utils.StaticCacheBust(),
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

	state.addCachedTags(data, r, input)

	err2 := templates["challenge-"+state.opt.ChallengeTemplate+".gohtml"].Execute(buf, input)
	if err2 != nil {
		// nested errors!
		panic(err2)
	} else {
		data.ResponseHeaders(w)
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
}
