package challenge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/condition"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/traits"
	"net"
	"net/http"
	"net/textproto"
	"time"
)

type requestDataContextKey struct {
}

func RequestDataFromContext(ctx context.Context) *RequestData {
	return ctx.Value(requestDataContextKey{}).(*RequestData)
}

type RequestId [16]byte

func (id RequestId) String() string {
	return hex.EncodeToString(id[:])
}

type RequestData struct {
	Id              RequestId
	Time            time.Time
	ChallengeVerify map[Id]VerifyResult
	ChallengeState  map[Id]VerifyState
	RemoteAddress   net.IP
	State           StateInterface

	r *http.Request

	fp     map[string]string
	header traits.Mapper
	query  traits.Mapper
}

func CreateRequestData(r *http.Request, state StateInterface) (*http.Request, *RequestData) {

	var data RequestData
	// generate random id, todo: is this fast?
	_, _ = rand.Read(data.Id[:])
	data.RemoteAddress = utils.GetRequestAddress(r, state.Settings().ClientIpHeader)
	data.ChallengeVerify = make(map[Id]VerifyResult, len(state.GetChallenges()))
	data.ChallengeState = make(map[Id]VerifyState, len(state.GetChallenges()))
	data.Time = time.Now().UTC()
	data.State = state
	data.r = r

	data.fp = make(map[string]string, 2)

	if fp := utils.GetTLSFingerprint(r); fp != nil {
		if ja3nPtr := fp.JA3N(); ja3nPtr != nil {
			ja3n := ja3nPtr.String()
			data.fp["ja3n"] = ja3n
			r.Header.Set("X-TLS-Fingerprint-JA3N", ja3n)
		}
		if ja4Ptr := fp.JA4(); ja4Ptr != nil {
			ja4 := ja4Ptr.String()
			data.fp["ja4"] = ja4
			r.Header.Set("X-TLS-Fingerprint-JA4", ja4)
		}
	}

	data.query = condition.NewValuesMap(r.URL.Query())
	data.header = condition.NewMIMEMap(textproto.MIMEHeader(r.Header))

	r = r.WithContext(context.WithValue(r.Context(), requestDataContextKey{}, &data))

	return r, &data
}

func (d *RequestData) ResolveName(name string) (any, bool) {
	switch name {
	case "host":
		return d.r.Host, true
	case "method":
		return d.r.Method, true
	case "remoteAddress":
		return d.RemoteAddress, true
	case "userAgent":
		return d.r.UserAgent(), true
	case "path":
		return d.r.URL.Path, true
	case "query":
		return d.query, true
	case "headers":
		return d.header, true
	case "fp":
		return d.fp, true
	default:
		return nil, false
	}
}

func (d *RequestData) Parent() cel.Activation {
	return nil
}

func (d *RequestData) EvaluateChallenges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var issuedChallenge string
	if q.Has(QueryArgChallenge) {
		issuedChallenge = q.Get(QueryArgChallenge)
	}
	for _, reg := range d.State.GetChallenges() {
		key := GetChallengeKeyForRequest(d.State, reg, d.Expiration(reg.Duration), r)
		verifyResult, verifyState, err := reg.VerifyChallengeToken(d.State.PublicKey(), key, r)
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			// clear invalid cookie
			utils.ClearCookie(utils.CookiePrefix+reg.Name, w, r)
		}

		// prevent evaluating the challenge if not solved
		if !verifyResult.Ok() && reg.Condition != nil {
			out, _, err := reg.Condition.Eval(d)
			// verify eligibility
			if err != nil {
				d.State.Logger(r).Error(err.Error(), "challenge", reg.Name)
			} else if out != nil && out.Type() == types.BoolType {
				if out.Equal(types.True) != types.True {
					// skip challenge match due to precondition!
					verifyResult = VerifyResultSkip
					continue
				}
			}
		}

		if !verifyResult.Ok() && issuedChallenge == reg.Name {
			// we issued the challenge, must skip to prevent loops
			verifyResult = VerifyResultSkip
		}
		d.ChallengeVerify[reg.Id()] = verifyResult
		d.ChallengeState[reg.Id()] = verifyState
	}

	if d.State.Settings().BackendIpHeader != "" {
		if d.State.Settings().ClientIpHeader != "" {
			r.Header.Del(d.State.Settings().ClientIpHeader)
		}
		r.Header.Set(d.State.Settings().BackendIpHeader, d.RemoteAddress.String())
	}

	// send these to client so we consistently get the headers
	//w.Header().Set("Accept-CH", "Sec-CH-UA, Sec-CH-UA-Platform")
	//w.Header().Set("Critical-CH", "Sec-CH-UA, Sec-CH-UA-Platform")
}

func (d *RequestData) Expiration(duration time.Duration) time.Time {
	return d.Time.Add(duration).Round(duration)
}

func (d *RequestData) HasValidChallenge(id Id) bool {
	return d.ChallengeVerify[id].Ok()
}

func (d *RequestData) Headers(headers http.Header) {
	headers.Set("X-Away-Id", d.Id.String())

	for id, result := range d.ChallengeVerify {
		if result.Ok() {
			c, ok := d.State.GetChallenge(id)
			if !ok {
				panic("challenge not found")
			}

			headers.Set(fmt.Sprintf("X-Away-Challenge-%s-Result", c.Name), result.String())
			headers.Set(fmt.Sprintf("X-Away-Challenge-%s-State", c.Name), d.ChallengeState[id].String())
		}
	}
}
