package wasm

import (
	"context"
	"encoding/json"
	"errors"
	"git.gammaspectra.live/git/go-away/lib/challenge/wasm/interface"
	"github.com/tetratelabs/wazero/api"
)

func MakeChallengeCall(ctx context.Context, mod api.Module, in _interface.MakeChallengeInput) (*_interface.MakeChallengeOutput, error) {
	makeChallengeFunc := mod.ExportedFunction("MakeChallenge")
	malloc := mod.ExportedFunction("malloc")
	free := mod.ExportedFunction("free")

	inData, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	mallocResult, err := malloc.Call(ctx, uint64(len(inData)))
	if err != nil {
		return nil, err
	}
	defer free.Call(ctx, mallocResult[0])
	if !mod.Memory().Write(uint32(mallocResult[0]), inData) {
		return nil, errors.New("could not write memory")
	}
	result, err := makeChallengeFunc.Call(ctx, uint64(_interface.NewAllocation(uint32(mallocResult[0]), uint32(len(inData)))))
	if err != nil {
		return nil, err
	}
	resultPtr := _interface.Allocation(result[0])
	outData, ok := mod.Memory().Read(resultPtr.Pointer(), resultPtr.Size())
	if !ok {
		return nil, errors.New("could not read result")
	}
	defer free.Call(ctx, uint64(resultPtr.Pointer()))

	var out _interface.MakeChallengeOutput
	err = json.Unmarshal(outData, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func VerifyChallengeCall(ctx context.Context, mod api.Module, in _interface.VerifyChallengeInput) (_interface.VerifyChallengeOutput, error) {
	verifyChallengeFunc := mod.ExportedFunction("VerifyChallenge")
	malloc := mod.ExportedFunction("malloc")
	free := mod.ExportedFunction("free")

	inData, err := json.Marshal(in)
	if err != nil {
		return _interface.VerifyChallengeOutputError, err
	}

	mallocResult, err := malloc.Call(ctx, uint64(len(inData)))
	if err != nil {
		return _interface.VerifyChallengeOutputError, err
	}
	defer free.Call(ctx, mallocResult[0])
	if !mod.Memory().Write(uint32(mallocResult[0]), inData) {
		return _interface.VerifyChallengeOutputError, errors.New("could not write memory")
	}
	result, err := verifyChallengeFunc.Call(ctx, uint64(_interface.NewAllocation(uint32(mallocResult[0]), uint32(len(inData)))))
	if err != nil {
		return _interface.VerifyChallengeOutputError, err
	}

	return _interface.VerifyChallengeOutput(result[0]), nil
}
