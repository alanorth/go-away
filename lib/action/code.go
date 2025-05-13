package action

import (
	"errors"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"log/slog"
	"net/http"
)

func init() {
	Register[policy.RuleActionCODE] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		params := CodeDefaultSettings

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

		if params.Code == 0 {
			return nil, errors.New("http-code not set")
		}

		return Code(params.Code), nil
	}
}

var CodeDefaultSettings = CodeSettings{}

type CodeSettings struct {
	Code int `yaml:"http-code"`
}

type Code int

func (a Code) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	data := challenge.RequestDataFromContext(r.Context())

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	data.ResponseHeaders(w)

	w.WriteHeader(int(a))
	return false, nil
}
