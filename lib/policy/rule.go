package policy

type RuleAction string

const (
	RuleActionPASS      RuleAction = "PASS"
	RuleActionDENY      RuleAction = "DENY"
	RuleActionBLOCK     RuleAction = "BLOCK"
	RuleActionCHALLENGE RuleAction = "CHALLENGE"
	RuleActionCHECK     RuleAction = "CHECK"
)

type Rule struct {
	Name       string   `yaml:"name"`
	Host       *string  `yaml:"host"`
	Conditions []string `yaml:"conditions"`

	Action string `yaml:"action"`

	Challenges []string `yaml:"challenges"`
}
