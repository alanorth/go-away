package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/challenge/wasm"
	"git.gammaspectra.live/git/go-away/lib/challenge/wasm/interface"
	"github.com/tetratelabs/wazero/api"
	"os"
	"reflect"
	"slices"
)

func main() {

	pathToTest := flag.String("wasm", "", "Path to test file")
	makeChallenge := flag.String("make-challenge", "", "Path to contents for MakeChallenge input")
	makeChallengeOutput := flag.String("make-challenge-out", "", "Path to contents for expected MakeChallenge output")
	verifyChallenge := flag.String("verify-challenge", "", "Path to contents for VerifyChallenge input")
	verifyChallengeOutput := flag.Uint64("verify-challenge-out", uint64(_interface.VerifyChallengeOutputOK), "Path to contents for expected VerifyChallenge output")

	flag.Parse()

	if *pathToTest == "" || *makeChallenge == "" || *makeChallengeOutput == "" || *verifyChallenge == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	wasmData, err := os.ReadFile(*pathToTest)
	if err != nil {
		panic(err)
	}

	runner := wasm.NewRunner(true)
	defer runner.Close()

	err = runner.Compile("test", wasmData)
	if err != nil {
		panic(err)
	}

	makeData, err := os.ReadFile(*makeChallenge)
	if err != nil {
		panic(err)
	}
	var makeIn _interface.MakeChallengeInput
	err = json.Unmarshal(makeData, &makeIn)
	if err != nil {
		panic(err)
	}

	makeOutData, err := os.ReadFile(*makeChallengeOutput)
	if err != nil {
		panic(err)
	}
	var makeOut _interface.MakeChallengeOutput
	err = json.Unmarshal(makeOutData, &makeOut)
	if err != nil {
		panic(err)
	}

	verifyData, err := os.ReadFile(*verifyChallenge)
	if err != nil {
		panic(err)
	}
	var verifyIn _interface.VerifyChallengeInput
	err = json.Unmarshal(verifyData, &verifyIn)
	if err != nil {
		panic(err)
	}

	if slices.Compare(makeIn.Key, verifyIn.Key) != 0 {
		panic("challenge keys do not match")
	}

	err = runner.Instantiate("test", func(ctx context.Context, mod api.Module) error {
		out, err := wasm.MakeChallengeCall(ctx, mod, makeIn)
		if err != nil {
			return err
		}

		if !reflect.DeepEqual(*out, makeOut) {
			return fmt.Errorf("challenge output did not match expected output, got %v, expected %v", *out, makeOut)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}

	err = runner.Instantiate("test", func(ctx context.Context, mod api.Module) error {
		out, err := wasm.VerifyChallengeCall(ctx, mod, verifyIn)
		if err != nil {
			return err
		}

		if out != _interface.VerifyChallengeOutput(*verifyChallengeOutput) {
			return fmt.Errorf("verify output did not match expected output, got %d expected %d", out, _interface.VerifyChallengeOutput(*verifyChallengeOutput))
		}
		return nil
	})
	if err != nil {
		panic(err)
	}

}
