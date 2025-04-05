package embed

import "embed"

//go:embed assets
var AssetsFs embed.FS

//go:embed challenge
var ChallengeFs embed.FS

//go:embed templates
var TemplatesFs embed.FS

//go:embed poison/*.poison
var PoisonFs embed.FS
