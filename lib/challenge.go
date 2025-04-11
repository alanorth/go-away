package lib

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/go-jose/go-jose/v4/jwt"
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

func getRequestScheme(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
		return proto
	}

	if r.TLS != nil {
		return "https"
	}

	return "http"
}

func getRequestAddress(r *http.Request, clientHeader string) net.IP {
	var ipStr string
	if clientHeader != "" {
		ipStr = r.Header.Get(clientHeader)
	}
	if ipStr != "" {
		// handle X-Forwarded-For
		ipStr = strings.Split(ipStr, ",")[0]
	}

	// fallback
	if ipStr == "" {
		parts := strings.Split(r.RemoteAddr, ":")
		// drop port
		ipStr = strings.Join(parts[:len(parts)-1], ":")
	}
	ipStr = strings.Trim(ipStr, "[]")
	return net.ParseIP(ipStr)
}

type ChallengeKey []byte

const ChallengeKeySize = sha256.Size

func (k *ChallengeKey) Set(flags ChallengeKeyFlags) {
	(*k)[0] |= uint8(flags)
}
func (k *ChallengeKey) Get(flags ChallengeKeyFlags) ChallengeKeyFlags {
	return ChallengeKeyFlags((*k)[0] & uint8(flags))
}
func (k *ChallengeKey) Unset(flags ChallengeKeyFlags) {
	(*k)[0] = (*k)[0] & ^(uint8(flags))
}

type ChallengeKeyFlags uint8

const (
	ChallengeKeyFlagIsIPv4 = ChallengeKeyFlags(1 << iota)
)

func ChallengeKeyFromString(s string) (ChallengeKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ChallengeKeySize {
		return nil, errors.New("invalid challenge key")
	}
	return ChallengeKey(b), nil
}

func (state *State) GetChallengeKeyForRequest(challengeName string, until time.Time, r *http.Request) ChallengeKey {
	data := RequestDataFromContext(r.Context())
	address := data.RemoteAddress
	hasher := sha256.New()
	hasher.Write([]byte("challenge\x00"))
	hasher.Write([]byte(challengeName))
	hasher.Write([]byte{0})
	hasher.Write(address.To16())
	hasher.Write([]byte{0})

	// specific headers
	for _, k := range []string{
		"Accept-Language",
		// General browser information
		"User-Agent",
		// TODO: not sent in preload
		//"Sec-Ch-Ua",
		//"Sec-Ch-Ua-Platform",
	} {
		hasher.Write([]byte(r.Header.Get(k)))
		hasher.Write([]byte{0})
	}
	hasher.Write([]byte{0})
	_ = binary.Write(hasher, binary.LittleEndian, until.UTC().Unix())
	hasher.Write([]byte{0})
	hasher.Write(state.publicKey)
	hasher.Write([]byte{0})

	sum := ChallengeKey(hasher.Sum(nil))

	sum[0] = 0

	if address.To4() != nil {
		// Is IPv4, mark
		sum.Set(ChallengeKeyFlagIsIPv4)
	}
	return ChallengeKey(sum)
}
