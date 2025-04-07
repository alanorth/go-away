package challenge

import (
	"net/http"
	"time"
)

type Result int

const (
	// ResultStop Stop testing other challenges and return
	ResultStop = Result(iota)
	// ResultContinue Test next
	ResultContinue
	// ResultPass  passed, return and proxy
	ResultPass
)

type Challenge struct {
	Path string

	Verify            func(key []byte, result string) (bool, error)
	VerifyProbability float64

	ServeStatic http.Handler

	ServeChallenge func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) Result

	ServeScript     http.Handler
	ServeScriptPath string

	ServeMakeChallenge   http.Handler
	ServeVerifyChallenge http.Handler
}
