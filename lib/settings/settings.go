package settings

import "maps"

type Settings struct {
	Bind Bind `json:"bind"`

	Backends map[string]Backend `json:"backends"`

	BindDebug   string `json:"bind-debug"`
	BindMetrics string `json:"bind-metrics"`

	Strings Strings `yaml:"strings"`

	// Links to add to challenge/error pages like privacy/impressum.
	Links []Link `yaml:"links"`

	ChallengeTemplate string `yaml:"challenge-template"`

	// ChallengeTemplateOverrides Key/Value overrides for the current chosen template
	// Replacements TODO:
	// Path -> go-away path
	ChallengeTemplateOverrides map[string]string `yaml:"challenge-template-overrides"`
}

type Link struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

var DefaultSettings = Settings{
	Strings:           DefaultStrings,
	ChallengeTemplate: "anubis",
	ChallengeTemplateOverrides: func() map[string]string {
		m := make(map[string]string)
		maps.Copy(m, map[string]string{
			"Theme": "",
			"Logo":  "",
		})
		return m
	}(),

	Bind: Bind{
		Address:         ":8080",
		Network:         "tcp",
		SocketMode:      "0770",
		Proxy:           false,
		TLSAcmeAutoCert: "",
	},
	Backends: make(map[string]Backend),
}
