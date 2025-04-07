package challenge

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"math/rand/v2"
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

type Id int

type Challenge struct {
	Id   Id
	Name string
	Path string

	Verify            func(key []byte, result string, r *http.Request) (bool, error)
	VerifyProbability float64

	ServeStatic http.Handler

	ServeChallenge func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) Result

	ServeScript     http.Handler
	ServeScriptPath string

	ServeMakeChallenge   http.Handler
	ServeVerifyChallenge http.Handler
}

type Token struct {
	Name   string `json:"name"`
	Key    []byte `json:"key"`
	Result []byte `json:"result,omitempty"`

	Expiry    *jwt.NumericDate `json:"exp,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`
}

func (c Challenge) IssueChallengeToken(privateKey ed25519.PrivateKey, key, result []byte, until time.Time) (token string, err error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       privateKey,
	}, nil)
	if err != nil {
		return "", err
	}

	expiry := jwt.NumericDate(until.Unix())
	notBefore := jwt.NumericDate(time.Now().UTC().AddDate(0, 0, -1).Unix())
	issuedAt := jwt.NumericDate(time.Now().UTC().Unix())

	token, err = jwt.Signed(signer).Claims(Token{
		Name:      c.Name,
		Key:       key,
		Result:    result,
		Expiry:    &expiry,
		NotBefore: &notBefore,
		IssuedAt:  &issuedAt,
	}).Serialize()
	if err != nil {
		return "", err
	}
	return token, nil
}

type VerifyResult int

const (
	VerifyResultNONE = VerifyResult(iota)
	VerifyResultFAIL

	// VerifyResultPASS Client just passed this challenge
	VerifyResultPASS
	VerifyResultOK
	VerifyResultBRIEF
	VerifyResultFULL
)

func (r VerifyResult) Ok() bool {
	return r > VerifyResultFAIL
}

func (r VerifyResult) String() string {
	switch r {
	case VerifyResultNONE:
		return "NONE"
	case VerifyResultFAIL:
		return "FAIL"
	case VerifyResultPASS:
		return "PASS"
	case VerifyResultOK:
		return "OK"
	case VerifyResultBRIEF:
		return "BRIEF"
	case VerifyResultFULL:
		return "FULL"
	default:
		panic("unsupported")
	}
}

var ErrVerifyKeyMismatch = errors.New("verify: key mismatch")
var ErrVerifyVerifyMismatch = errors.New("verify: verification mismatch")

func (c Challenge) VerifyChallengeToken(publicKey ed25519.PublicKey, expectedKey []byte, r *http.Request) (VerifyResult, error) {
	cookie, err := r.Cookie(utils.CookiePrefix + c.Name)
	if err != nil {
		return VerifyResultNONE, err
	}
	if cookie == nil {
		return VerifyResultNONE, http.ErrNoCookie
	}

	token, err := jwt.ParseSigned(cookie.Value, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return VerifyResultFAIL, err
	}

	var i Token
	err = token.Claims(publicKey, &i)
	if err != nil {
		return VerifyResultFAIL, err
	}

	if i.Name != c.Name {
		return VerifyResultFAIL, errors.New("token invalid name")
	}
	if i.Expiry == nil && i.Expiry.Time().Compare(time.Now()) < 0 {
		return VerifyResultFAIL, errors.New("token expired")
	}
	if i.NotBefore == nil && i.NotBefore.Time().Compare(time.Now()) > 0 {
		return VerifyResultFAIL, errors.New("token not valid yet")
	}

	if bytes.Compare(expectedKey, i.Key) != 0 {
		return VerifyResultFAIL, ErrVerifyKeyMismatch
	}

	if c.Verify != nil {
		if rand.Float64() < c.VerifyProbability {
			// random spot check
			if ok, err := c.Verify(expectedKey, string(i.Result), r); err != nil {
				return VerifyResultFAIL, err
			} else if !ok {
				return VerifyResultFAIL, ErrVerifyVerifyMismatch
			}
			return VerifyResultFULL, nil
		} else {
			return VerifyResultBRIEF, nil
		}
	}
	return VerifyResultOK, nil
}
