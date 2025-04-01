package go_away

import "embed"

//go:embed assets
var AssetsFs embed.FS

//go:embed challenge
var ChallengeFs embed.FS

//go:embed templates
var TemplatesFs embed.FS
