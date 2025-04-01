package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"git.gammaspectra.live/git/go-away/challenge"
	"git.gammaspectra.live/git/go-away/challenge/inline"
	"math/bits"
	"strconv"
)

//go:generate tinygo build -target wasip1 -buildmode=c-shared -opt=2 -scheduler=none -gc=leaking -no-debug -o runtime.wasm runtime.go
func main() {

}

func getChallenge(key []byte, params map[string]string) ([]byte, uint64) {
	difficulty := uint64(20)
	var err error
	if diffStr, ok := params["difficulty"]; ok {
		difficulty, err = strconv.ParseUint(diffStr, 10, 64)
		if err != nil {
			panic(err)
		}
	}
	hasher := sha256.New()
	hasher.Write(binary.LittleEndian.AppendUint64(nil, difficulty))
	hasher.Write(key)
	return hasher.Sum(nil), difficulty
}

//go:wasmexport MakeChallenge
func MakeChallenge(in challenge.Allocation) (out challenge.Allocation) {
	return challenge.MakeChallengeDecode(func(in challenge.MakeChallengeInput, out *challenge.MakeChallengeOutput) {
		c, difficulty := getChallenge(in.Key, in.Parameters)

		// create target
		target := make([]byte, len(c))
		nBits := difficulty
		for i := 0; i < len(target); i++ {
			var v uint8
			for j := 0; j < 8; j++ {
				v <<= 1
				if nBits == 0 {
					v |= 1
				} else {
					nBits--
				}
			}
			target[i] = v
		}

		dst := make([]byte, inline.EncodedLen(len(c)))
		dst = dst[:inline.Encode(dst, c)]

		targetDst := make([]byte, inline.EncodedLen(len(target)))
		targetDst = targetDst[:inline.Encode(targetDst, target)]

		out.Data = []byte("{\"challenge\": \"" + string(dst) + "\", \"target\": \"" + string(targetDst) + "\", \"difficulty\": " + strconv.FormatUint(difficulty, 10) + "}")
		out.Headers.Set("Content-Type", "application/json; charset=utf-8")
	}, in)
}

//go:wasmexport VerifyChallenge
func VerifyChallenge(in challenge.Allocation) (out challenge.VerifyChallengeOutput) {
	return challenge.VerifyChallengeDecode(func(in challenge.VerifyChallengeInput) challenge.VerifyChallengeOutput {
		c, difficulty := getChallenge(in.Key, in.Parameters)

		result := make([]byte, inline.DecodedLen(len(in.Result)))
		n, err := inline.Decode(result, in.Result)
		if err != nil {
			panic(err)
		}
		result = result[:n]

		// verify we used same challenge
		if subtle.ConstantTimeCompare(result[:len(result)-8], c) != 1 {
			return challenge.VerifyChallengeOutputFailed
		}

		hash := sha256.Sum256(result)

		var leadingZeroesCount int
		for i := 0; i < len(hash); i++ {
			leadingZeroes := bits.LeadingZeros8(hash[i])
			leadingZeroesCount += leadingZeroes
			if leadingZeroes < 8 {
				break
			}
		}

		if leadingZeroesCount < int(difficulty) {
			return challenge.VerifyChallengeOutputFailed
		}

		return challenge.VerifyChallengeOutputOK
	}, in)
}
