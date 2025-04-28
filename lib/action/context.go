package action

import (
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"log/slog"
	"net/http"
)

func init() {
	Register[policy.RuleActionCONTEXT] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		params := ContextDefaultSettings

		if settings != nil {
			ymlData, err := settings.MarshalYAML()
			if err != nil {
				return nil, err
			}
			err = yaml.Unmarshal(ymlData, &params)
			if err != nil {
				return nil, err
			}
		}

		return Context{
			opts: params,
		}, nil
	}
}

var ContextDefaultSettings = ContextSettings{}

type ContextSettings struct {
	ContextSet      map[string]string `yaml:"context-set"`
	ResponseHeaders map[string]string `yaml:"response-headers"`
}

type Context struct {
	opts ContextSettings
}

func (a Context) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	data := challenge.RequestDataFromContext(r.Context())
	for k, v := range a.opts.ContextSet {
		data.SetOpt(k, v)
	}

	for k, v := range a.opts.ResponseHeaders {
		w.Header().Set(k, v)
	}

	return true, nil
}
