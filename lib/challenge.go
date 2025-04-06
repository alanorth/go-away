package lib

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"
)

type ChallengeInformation struct {
	Name   string `json:"name"`
	Key    []byte `json:"key"`
	Result []byte `json:"result"`

	Expiry    *jwt.NumericDate `json:"exp,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`
}

func getRequestAddress(r *http.Request) net.IP {
	//TODO: verified upstream
	ipStr := r.Header.Get("X-Real-Ip")
	if ipStr == "" {
		ipStr = strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]
	}
	if ipStr == "" {
		parts := strings.Split(r.RemoteAddr, ":")
		// drop port
		ipStr = strings.Join(parts[:len(parts)-1], ":")
	}
	return net.ParseIP(ipStr)
}

func (state *State) GetChallengeKeyForRequest(name string, until time.Time, r *http.Request) []byte {
	hasher := sha256.New()
	hasher.Write([]byte("challenge\x00"))
	hasher.Write([]byte(name))
	hasher.Write([]byte{0})
	hasher.Write(getRequestAddress(r).To16())
	hasher.Write([]byte{0})

	// specific headers
	for _, k := range []string{
		"Accept-Language",
		// General browser information
		"User-Agent",
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Platform",
	} {
		hasher.Write([]byte(r.Header.Get(k)))
		hasher.Write([]byte{0})
	}
	hasher.Write([]byte{0})
	_ = binary.Write(hasher, binary.LittleEndian, until.UTC().Unix())
	hasher.Write([]byte{0})
	hasher.Write(state.publicKey)
	hasher.Write([]byte{0})

	return hasher.Sum(nil)
}

func (state *State) IssueChallengeToken(name string, key, result []byte, until time.Time) (token string, err error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       state.privateKey,
	}, nil)
	if err != nil {
		return "", err
	}

	expiry := jwt.NumericDate(until.Unix())
	notBefore := jwt.NumericDate(time.Now().UTC().AddDate(0, 0, -1).Unix())
	issuedAt := jwt.NumericDate(time.Now().UTC().Unix())

	token, err = jwt.Signed(signer).Claims(ChallengeInformation{
		Name:      name,
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

func (state *State) VerifyChallengeToken(name string, expectedKey []byte, w http.ResponseWriter, r *http.Request) (ok bool, err error) {
	c, ok := state.Challenges[name]
	if !ok {
		return false, errors.New("challenge not found")
	}

	cookie, err := r.Cookie(CookiePrefix + name)
	if err != nil {
		// fallback: fetch cookie from response
		// TODO: implemented in go1.23, port back
		/*
			if setCookies, ok := w.Header()["Set-Cookie"]; ok {
				for _, setCookie := range setCookies {
					newCookie, err := http.ParseSetCookie(setCookie)
					if err != nil {
						continue
					}
					// keep processing to find last set cookie
					if newCookie.Name == name {
						cookie = newCookie
					}
				}
			}
		*/
	}
	if err != nil {
		return false, err
	}
	if cookie == nil {
		return false, http.ErrNoCookie
	}

	token, err := jwt.ParseSigned(cookie.Value, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return false, err
	}

	var i ChallengeInformation
	err = token.Claims(state.publicKey, &i)
	if err != nil {
		return false, err
	}

	if i.Name != name {
		return false, errors.New("token invalid name")
	}
	if i.Expiry == nil && i.Expiry.Time().Compare(time.Now()) < 0 {
		return false, errors.New("token expired")
	}
	if i.NotBefore == nil && i.NotBefore.Time().Compare(time.Now()) > 0 {
		return false, errors.New("token not valid yet")
	}

	if bytes.Compare(expectedKey, i.Key) != 0 {
		return false, errors.New("key mismatch")
	}

	if c.Verify != nil {
		if rand.Float64() < c.VerifyProbability {
			// random spot check
			if ok, err := c.Verify(expectedKey, string(i.Result)); err != nil {
				return false, err
			} else if !ok {
				return false, errors.New("failed challenge verification")
			}
			r.Header.Set(fmt.Sprintf("X-Away-Challenge-%s-Verify", name), "FULL")
		} else {
			r.Header.Set(fmt.Sprintf("X-Away-Challenge-%s-Verify", name), "BRIEF")
		}
	}
	r.Header.Set(fmt.Sprintf("X-Away-Challenge-%s-Verify", name), "CHECK")

	return true, nil
}
