package policy

import (
	"git.gammaspectra.live/git/go-away/utils"
	"net/http"
)

type Settings struct {
	Cache                  utils.Cache
	Backends               map[string]http.Handler
	PrivateKeySeed         []byte
	Debug                  bool
	PackageName            string
	ChallengeTemplate      string
	ChallengeTemplateTheme string
	ClientIpHeader         string
	BackendIpHeader        string

	ChallengeResponseCode int
}
