//go:build !tinygo || !wasip1

package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"slices"
)

type Runner struct {
	context context.Context
	runtime wazero.Runtime

	modules map[string]wazero.CompiledModule
}

func NewRunner(useNativeCompiler bool) *Runner {
	var r Runner
	r.context = context.Background()
	var runtimeConfig wazero.RuntimeConfig
	if useNativeCompiler {
		runtimeConfig = wazero.NewRuntimeConfigCompiler()
	} else {
		runtimeConfig = wazero.NewRuntimeConfigInterpreter()
	}
	r.runtime = wazero.NewRuntimeWithConfig(r.context, runtimeConfig)
	wasi_snapshot_preview1.MustInstantiate(r.context, r.runtime)

	r.modules = make(map[string]wazero.CompiledModule)

	return &r
}

func (r *Runner) Compile(key string, binary []byte) error {
	module, err := r.runtime.CompileModule(r.context, binary)
	if err != nil {
		return err
	}

	// check interface
	functions := module.ExportedFunctions()
	if f, ok := functions["MakeChallenge"]; ok {
		if slices.Compare(f.ParamTypes(), []api.ValueType{api.ValueTypeI64}) != 0 {
			return fmt.Errorf("MakeChallenge does not follow parameter interface")
		}
		if slices.Compare(f.ResultTypes(), []api.ValueType{api.ValueTypeI64}) != 0 {
			return fmt.Errorf("MakeChallenge does not follow result interface")
		}
	} else {
		module.Close(r.context)
		return errors.New("no MakeChallenge exported")
	}

	if f, ok := functions["VerifyChallenge"]; ok {
		if slices.Compare(f.ParamTypes(), []api.ValueType{api.ValueTypeI64}) != 0 {
			return fmt.Errorf("VerifyChallenge does not follow parameter interface")
		}
		if slices.Compare(f.ResultTypes(), []api.ValueType{api.ValueTypeI64}) != 0 {
			return fmt.Errorf("VerifyChallenge does not follow result interface")
		}
	} else {
		module.Close(r.context)
		return errors.New("no VerifyChallenge exported")
	}

	if f, ok := functions["malloc"]; ok {
		if slices.Compare(f.ParamTypes(), []api.ValueType{api.ValueTypeI32}) != 0 {
			return fmt.Errorf("malloc does not follow parameter interface")
		}
		if slices.Compare(f.ResultTypes(), []api.ValueType{api.ValueTypeI32}) != 0 {
			return fmt.Errorf("malloc does not follow result interface")
		}
	} else {
		module.Close(r.context)
		return errors.New("no malloc exported")
	}

	if f, ok := functions["free"]; ok {
		if slices.Compare(f.ParamTypes(), []api.ValueType{api.ValueTypeI32}) != 0 {
			return fmt.Errorf("free does not follow parameter interface")
		}
		if slices.Compare(f.ResultTypes(), []api.ValueType{}) != 0 {
			return fmt.Errorf("free does not follow result interface")
		}
	} else {
		module.Close(r.context)
		return errors.New("no free exported")
	}

	r.modules[key] = module
	return nil
}

func (r *Runner) Close() {
	for _, module := range r.modules {
		module.Close(r.context)
	}
	r.runtime.Close(r.context)
}

var ErrModuleNotFound = errors.New("module not found")

func (r *Runner) Instantiate(key string, f func(ctx context.Context, mod api.Module) error) (err error) {
	compiledModule, ok := r.modules[key]
	if !ok {
		return ErrModuleNotFound
	}
	mod, err := r.runtime.InstantiateModule(
		r.context,
		compiledModule,
		wazero.NewModuleConfig().WithName(key).WithStartFunctions("_initialize"),
	)
	if err != nil {
		return err
	}
	defer mod.Close(r.context)

	return f(r.context, mod)
}

func MakeChallengeCall(ctx context.Context, mod api.Module, in MakeChallengeInput) (*MakeChallengeOutput, error) {
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
	if err != nil {
		return VerifyChallengeOutputError, err
	}

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
