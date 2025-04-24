package settings

import "maps"

type Strings map[string]string

var DefaultStrings = make(Strings).set(map[string]string{
	"challenge_are_you_bot": "Checking you are not a bot",
	"error":                 "Oh no!",
})

func (s Strings) set(v map[string]string) Strings {
	maps.Copy(s, v)
	return s
}

func (s Strings) Get(value string) string {
	v, ok := (s)[value]
	if !ok {
		// fallback
		return "string:" + value
	}
	return v
}
