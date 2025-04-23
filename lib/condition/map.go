package condition

import (
	"fmt"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"net/textproto"
	"reflect"
	"strings"
)

type mimeLike struct {
	m textproto.MIMEHeader
}

func (a mimeLike) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return nil, fmt.Errorf("type conversion error from map to '%v'", typeDesc)
}

func (a mimeLike) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.MapType:
		return a
	case types.TypeType:
		return types.MapType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", types.MapType, typeVal)
}

func (a mimeLike) Equal(other ref.Val) ref.Val {
	return types.Bool(false)
}

func (a mimeLike) Type() ref.Type {
	return types.MapType
}

func (a mimeLike) Value() any {
	return a.m
}

func (a mimeLike) Contains(key ref.Val) ref.Val {
	_, found := a.Find(key)
	return types.Bool(found)
}

func (a mimeLike) Get(key ref.Val) ref.Val {
	v, found := a.Find(key)
	if !found {
		return types.ValOrErr(v, "no such key: %v", key)
	}
	return v
}

func (a mimeLike) Iterator() traits.Iterator {
	panic("implement me")
}

func (a mimeLike) IsZeroValue() bool {
	return len(a.m) == 0
}

func (a mimeLike) Size() ref.Val {
	return types.Int(len(a.m))
}

func (a mimeLike) Find(key ref.Val) (ref.Val, bool) {
	k, ok := key.(types.String)
	if !ok {
		return nil, false
	}

	return singleVal(a.m.Values(string(k)), true)
}

type valuesLike struct {
	m map[string][]string
}

func (a valuesLike) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return nil, fmt.Errorf("type conversion error from map to '%v'", typeDesc)
}

func (a valuesLike) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.MapType:
		return a
	case types.TypeType:
		return types.MapType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", types.MapType, typeVal)
}

func (a valuesLike) Equal(other ref.Val) ref.Val {
	return types.Bool(false)
}

func (a valuesLike) Type() ref.Type {
	return types.MapType
}

func (a valuesLike) Value() any {
	return a.m
}

func (a valuesLike) Contains(key ref.Val) ref.Val {
	_, found := a.Find(key)
	return types.Bool(found)
}

func (a valuesLike) Get(key ref.Val) ref.Val {
	v, found := a.Find(key)
	if !found {
		return types.ValOrErr(v, "no such key: %v", key)
	}
	return v
}

func (a valuesLike) Iterator() traits.Iterator {
	panic("implement me")
}

func (a valuesLike) IsZeroValue() bool {
	return len(a.m) == 0
}

func (a valuesLike) Size() ref.Val {
	return types.Int(len(a.m))
}

func (a valuesLike) Find(key ref.Val) (ref.Val, bool) {
	k, ok := key.(types.String)
	if !ok {
		return nil, false
	}

	val, ok := a.m[string(k)]
	return singleVal(val, ok)
}

func singleVal(values []string, ok bool) (ref.Val, bool) {
	if len(values) == 0 || !ok {
		return nil, false
	}
	if len(values) > 1 {
		return types.String(strings.Join(values, ",")), true
	}
	return types.String(values[0]), true
}

func NewMIMEMap(m textproto.MIMEHeader) traits.Mapper {
	return mimeLike{m: m}
}

func NewValuesMap(m map[string][]string) traits.Mapper {
	return valuesLike{m: m}
}
