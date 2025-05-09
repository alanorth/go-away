package challenge

import (
	http_cel "codeberg.org/gone/http-cel"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/traits"
	"maps"
	"net/http"
	"net/netip"
	"net/textproto"
	"strings"
	"time"
)

type requestDataContextKey struct {
}

func RequestDataFromContext(ctx context.Context) *RequestData {
	val := ctx.Value(requestDataContextKey{})
	if val == nil {
		return nil
	}
	return val.(*RequestData)
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
	RemoteAddress   netip.AddrPort
	State           StateInterface
	CookiePrefix    string

	ExtraHeaders http.Header

	r *http.Request

	fp     map[string]string
	header traits.Mapper
	query  traits.Mapper

	opts map[string]string
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

	data.ExtraHeaders = make(http.Header)

	data.fp = make(map[string]string, 2)

	if fp := utils.GetTLSFingerprint(r); fp != nil {
		if ja3nPtr := fp.JA3N(); ja3nPtr != nil {
			ja3n := ja3nPtr.String()
			data.fp["ja3n"] = ja3n
		}
		if ja4Ptr := fp.JA4(); ja4Ptr != nil {
			ja4 := ja4Ptr.String()
			data.fp["ja4"] = ja4
		}
	}

	q := r.URL.Query()
	// delete query parameters that were set by go-away
	for k := range q {
		if strings.HasPrefix(k, QueryArgPrefix) {
			q.Del(k)
		}
	}

	data.query = http_cel.NewValuesMap(q)
	data.header = http_cel.NewMIMEMap(textproto.MIMEHeader(r.Header))
	data.opts = make(map[string]string)

	sum := sha256.New()
	sum.Write([]byte(r.Host))
	sum.Write([]byte{0})
	sum.Write(data.NetworkPrefix().AsSlice())
	sum.Write([]byte{0})
	sum.Write(state.PublicKey())
	sum.Write([]byte{0})
	data.CookiePrefix = utils.CookiePrefix + hex.EncodeToString(sum.Sum(nil)[:6]) + "-"

	r = r.WithContext(context.WithValue(r.Context(), requestDataContextKey{}, &data))
	r = utils.SetRemoteAddress(r, data.RemoteAddress)
	data.r = r

	return r, &data
}

func (d *RequestData) ResolveName(name string) (any, bool) {
	switch name {
	case "host":
		return d.r.Host, true
	case "method":
		return d.r.Method, true
	case "remoteAddress":
		return d.RemoteAddress.Addr().AsSlice(), true
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

func (d *RequestData) NetworkPrefix() netip.Addr {
	address := d.RemoteAddress.Addr().Unmap()
	if address.Is4() {
		// Take a /24 for IPv4
		prefix, _ := address.Prefix(24)
		return prefix.Addr()
	} else {
		// Take a /64 for IPv6
		prefix, _ := address.Prefix(64)
		return prefix.Addr()
	}
}

const (
	RequestOptBackendHost   = "backend-host"
	RequestOptCacheMetaTags = "proxy-meta-tags"
)

func (d *RequestData) SetOpt(n, v string) {
	d.opts[n] = v
}

func (d *RequestData) GetOpt(n, def string) string {
	v, ok := d.opts[n]
	if !ok {
		return def
	}
	return v
}

func (d *RequestData) GetOptBool(n string, def bool) bool {
	v, ok := d.opts[n]
	if !ok {
		return def
	}
	switch v {
	case "true", "t", "1", "yes", "yep", "y", "ok":
		return true
	case "false", "f", "0", "no", "nope", "n", "err":
		return false
	default:
		return def
	}
}

func (d *RequestData) BackendHost() (http.Handler, string) {
	host := d.r.Host

	if opt := d.GetOpt(RequestOptBackendHost, ""); opt != "" && opt != host {
		host = d.r.Host
	}

	return d.State.GetBackend(host), host
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
			utils.ClearCookie(d.CookiePrefix+reg.Name, w, r)
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

func (d *RequestData) RequestHeaders(headers http.Header) {
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

	if ja4, ok := d.fp["fp4"]; ok {
		headers.Set("X-TLS-Fingerprint-JA4", ja4)
	}

	if ja3n, ok := d.fp["ja3n"]; ok {
		headers.Set("X-TLS-Fingerprint-JA3N", ja3n)
	}

	maps.Copy(headers, d.ExtraHeaders)
}
