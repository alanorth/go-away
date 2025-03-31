package challenge

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
)

const ChallengeKeySize = sha256.Size

type MakeChallenge func(in Allocation) (out Allocation)

type Allocation uint64

func NewAllocation(ptr, size uint32) Allocation {
	return Allocation((uint64(ptr) << uint64(32)) | uint64(size))
}

func (p Allocation) Pointer() uint32 {
	return uint32(p >> 32)
}
func (p Allocation) Size() uint32 {
	return uint32(p)
}

func MakeChallengeDecode(callback func(in MakeChallengeInput, out *MakeChallengeOutput), in Allocation) (out Allocation) {
	outStruct := &MakeChallengeOutput{}
	var inStruct MakeChallengeInput

	inData := PtrToBytes(in.Pointer(), in.Size())

	err := json.Unmarshal(inData, &inStruct)
	if err != nil {
		outStruct.Code = 500
		outStruct.Error = err.Error()
	} else {
		outStruct.Code = 200
		outStruct.Headers = make(http.Header)

		func() {
			// encapsulate err
			defer func() {
				if recovered := recover(); recovered != nil {
					if outStruct.Code == 200 {
						outStruct.Code = 500
					}
					if err, ok := recovered.(error); ok {
						outStruct.Error = err.Error()
					} else {
						outStruct.Error = fmt.Sprintf("%v", recovered)
					}
				}
			}()
			callback(inStruct, outStruct)
		}()
	}

	if len(outStruct.Headers) == 0 {
		outStruct.Headers = nil
	}

	outData, err := json.Marshal(outStruct)
	if err != nil {
		panic(err)
	}

	return NewAllocation(BytesToLeakedPtr(outData))
}

func VerifyChallengeDecode(callback func(in VerifyChallengeInput) VerifyChallengeOutput, in Allocation) (out VerifyChallengeOutput) {
	var inStruct VerifyChallengeInput

	inData := PtrToBytes(in.Pointer(), in.Size())

	err := json.Unmarshal(inData, &inStruct)
	if err != nil {
		return VerifyChallengeOutputError
	} else {
		func() {
			// encapsulate err
			defer func() {
				if recovered := recover(); recovered != nil {
					out = VerifyChallengeOutputError
				}
			}()
			out = callback(inStruct)
		}()
	}

	return out
}

type MakeChallengeInput struct {
	Key []byte `json:"key"`

	Parameters map[string]string `json:"parameters,omitempty"`

	Headers http.Header `json:"headers,omitempty"`
	Data    []byte      `json:"data,omitempty"`
}

type MakeChallengeOutput struct {
	Data    []byte      `json:"data"`
	Code    int         `json:"code"`
	Headers http.Header `json:"headers,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type VerifyChallengeInput struct {
	Key        []byte            `json:"key"`
	Parameters map[string]string `json:"parameters,omitempty"`

	Result []byte `json:"result,omitempty"`
}

type VerifyChallengeOutput uint64

const (
	VerifyChallengeOutputOK = VerifyChallengeOutput(iota)
	VerifyChallengeOutputFailed
	VerifyChallengeOutputError
)
