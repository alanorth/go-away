package policy

type Challenge struct {
	Mode  string  `yaml:"mode"`
	Asset *string `yaml:"asset,omitempty"`
	Url   *string `yaml:"url,omitempty"`

	Parameters map[string]string `json:"parameters,omitempty"`
	Runtime    struct {
		Mode        string  `yaml:"mode,omitempty"`
		Asset       string  `yaml:"asset,omitempty"`
		Probability float64 `yaml:"probability,omitempty"`
	} `yaml:"runtime"`
}
