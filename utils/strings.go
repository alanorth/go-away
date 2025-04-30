package utils

import (
	"html/template"
	"maps"
)

type Strings map[string]string

func (s Strings) set(v map[string]string) Strings {
	maps.Copy(s, v)
	return s
}

func (s Strings) Get(value string) template.HTML {
	v, ok := (s)[value]
	if !ok {
		// fallback
		return template.HTML("string:" + value)
	}
	return template.HTML(v)
}

func NewStrings[T ~map[string]string](v T) Strings {
	return make(Strings).set(v)
}
