//go:build !tinygo

package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/tetratelabs/wazero/api"
)

func MakeChallengeCall(ctx context.Context, mod api.Module, in MakeChallengeInput) (*MakeChallengeOutput, error) {
	makeChallengeFunc := mod.ExportedFunction("MakeChallenge")
	malloc := mod.ExportedFunction("malloc")
	free := mod.ExportedFunction("free")

	inData, err := json.Marshal(in)

	mallocResult, err := malloc.Call(ctx, uint64(len(inData)))
	if err != nil {
		return nil, err
	}
	defer free.Call(ctx, mallocResult[0])
	if !mod.Memory().Write(uint32(mallocResult[0]), inData) {
		return nil, errors.New("could not write memory")
	}
	result, err := makeChallengeFunc.Call(ctx, uint64(NewAllocation(uint32(mallocResult[0]), uint32(len(inData)))))
	if err != nil {
		return nil, err
	}
	resultPtr := Allocation(result[0])
	outData, ok := mod.Memory().Read(resultPtr.Pointer(), resultPtr.Size())
	if !ok {
		return nil, errors.New("could not read result")
	}
	defer free.Call(ctx, uint64(resultPtr.Pointer()))

	var out MakeChallengeOutput
	err = json.Unmarshal(outData, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func VerifyChallengeCall(ctx context.Context, mod api.Module, in VerifyChallengeInput) (VerifyChallengeOutput, error) {
	verifyChallengeFunc := mod.ExportedFunction("VerifyChallenge")
	malloc := mod.ExportedFunction("malloc")
	free := mod.ExportedFunction("free")

	inData, err := json.Marshal(in)

	mallocResult, err := malloc.Call(ctx, uint64(len(inData)))
	if err != nil {
		return VerifyChallengeOutputError, err
	}
	defer free.Call(ctx, mallocResult[0])
	if !mod.Memory().Write(uint32(mallocResult[0]), inData) {
		return VerifyChallengeOutputError, errors.New("could not write memory")
	}
	result, err := verifyChallengeFunc.Call(ctx, uint64(NewAllocation(uint32(mallocResult[0]), uint32(len(inData)))))
	if err != nil {
		return VerifyChallengeOutputError, err
	}

	return VerifyChallengeOutput(result[0]), nil
}

func PtrToBytes(ptr uint32, size uint32) []byte   { panic("not implemented") }
func BytesToPtr(s []byte) (uint32, uint32)        { panic("not implemented") }
func BytesToLeakedPtr(s []byte) (uint32, uint32)  { panic("not implemented") }
func PtrToString(ptr uint32, size uint32) string  { panic("not implemented") }
func StringToPtr(s string) (uint32, uint32)       { panic("not implemented") }
func StringToLeakedPtr(s string) (uint32, uint32) { panic("not implemented") }
