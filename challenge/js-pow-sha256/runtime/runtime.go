package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"git.gammaspectra.live/git/go-away/challenge"
	"strconv"
	"strings"
)

//go:generate tinygo build -target wasip1 -buildmode=c-shared -scheduler=none -gc=leaking -o runtime.wasm runtime.go
func main() {

}

func getChallenge(key []byte, params map[string]string) ([]byte, uint64) {
	difficulty := uint64(5)
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
		type Result struct {
			Challenge  string `json:"challenge"`
			Difficulty uint64 `json:"difficulty"`
		}

		challenge, difficulty := getChallenge(in.Key, in.Parameters)

		data, err := json.Marshal(Result{
			Challenge:  hex.EncodeToString(challenge),
			Difficulty: difficulty,
		})
		if err != nil {
			panic(err)
		}
		out.Data = data
		out.Headers.Set("Content-Type", "text/javascript; charset=utf-8")
	}, in)
}

//go:wasmexport VerifyChallenge
func VerifyChallenge(in challenge.Allocation) (out challenge.VerifyChallengeOutput) {
	return challenge.VerifyChallengeDecode(func(in challenge.VerifyChallengeInput) challenge.VerifyChallengeOutput {
		c, difficulty := getChallenge(in.Key, in.Parameters)

		type Result struct {
			Hash  string `json:"hash"`
			Nonce uint64 `json:"nonce"`
		}
		var result Result
		err := json.Unmarshal(in.Result, &result)

		if err != nil {
			panic(err)
		}

		if !strings.HasPrefix(result.Hash, strings.Repeat("0", int(difficulty))) {
			return challenge.VerifyChallengeOutputFailed
		}

		resultBinary, err := hex.DecodeString(result.Hash)
		if err != nil {
			panic(err)
		}

		buf := make([]byte, 0, len(c)+8)
		buf = append(buf, c[:]...)
		buf = binary.LittleEndian.AppendUint64(buf, result.Nonce)
		calculated := sha256.Sum256(buf)

		if subtle.ConstantTimeCompare(resultBinary, calculated[:]) != 1 {
			return challenge.VerifyChallengeOutputFailed
		}

		return challenge.VerifyChallengeOutputOK
	}, in)
}
