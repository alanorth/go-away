package cookie

import (
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"github.com/goccy/go-yaml/ast"
	"net/http"
	"time"
)

func init() {
	challenge.Runtimes[Key] = FillRegistration
}

const Key = "cookie"

func FillRegistration(state challenge.StateInterface, reg *challenge.Registration, parameters ast.Node) error {
	reg.Class = challenge.ClassBlocking

	reg.IssueChallenge = func(w http.ResponseWriter, r *http.Request, key challenge.Key, expiry time.Time) challenge.VerifyResult {
		data := challenge.RequestDataFromContext(r.Context())
		data.IssueChallengeToken(reg, key, nil, expiry, true)

		uri, err := challenge.RedirectUrl(r, reg)
		if err != nil {
			return challenge.VerifyResultFail
		}

		data.ResponseHeaders(w)
		http.Redirect(w, r, uri.String(), http.StatusTemporaryRedirect)
		return challenge.VerifyResultNone
	}

	return nil
}
