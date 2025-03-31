package go_away

import (
	"fmt"
	"github.com/google/cel-go/cel"
	"strings"
)

type Condition struct {
	Expression *cel.Ast
}

const (
	OperatorOr  = "||"
	OperatorAnd = "&&"
)

func ConditionFromStrings(env *cel.Env, operator string, conditions ...string) (*cel.Ast, error) {
	var asts []*cel.Ast
	for _, c := range conditions {
		ast, issues := env.Compile(c)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("condition %s: %s", issues.Err(), c)
		}
		asts = append(asts, ast)
	}

	return MergeConditions(env, operator, asts...)
}

func MergeConditions(env *cel.Env, operator string, conditions ...*cel.Ast) (*cel.Ast, error) {
	if len(conditions) == 0 {
		return nil, nil
	} else if len(conditions) == 1 {
		return conditions[0], nil
	}
	var asts []string
	for _, c := range conditions {
		ast, err := cel.AstToString(c)
		if err != nil {
			return nil, err
		}
		asts = append(asts, "("+ast+")")
	}

	condition := strings.Join(asts, " "+operator+" ")
	ast, issues := env.Compile(condition)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	return ast, nil
}
