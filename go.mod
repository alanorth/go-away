module git.gammaspectra.live/git/go-away

go 1.22.0

toolchain go1.22.12

require (
	codeberg.org/meta/gzipped/v2 v2.0.0-20231111234332-aa70c3194756
	github.com/andybalholm/brotli v1.1.1
	github.com/go-jose/go-jose/v4 v4.0.5
	github.com/google/cel-go v0.24.1
	github.com/itchyny/gojq v0.12.17
	github.com/klauspost/compress v1.18.0
	github.com/tetratelabs/wazero v1.9.0
	github.com/yl2chen/cidranger v1.0.2
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cel.dev/expr v0.23.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/itchyny/timefmt-go v0.1.6 // indirect
	github.com/kevinpollet/nego v0.0.0-20211010160919-a65cd48cee43 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/exp v0.0.0-20250210185358-939b2ce775ac // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

// Used by github.com/antlr4-go/antlr v4.13.0 via github.com/google/cel-go
// Ensure we have no other exp package usages by only proxying the slices functions in that package
// Newer versions than v0.0.0-20250210185358-939b2ce775ac are not supported by Go 1.22
replace golang.org/x/exp v0.0.0 => ./utils/exp

// Pin latest versions to support Go 1.22 to prevent a package update from changing them
// TODO: remove this when Go 1.22+ is supported by other higher users
replace (
	google.golang.org/genproto/googleapis/api => google.golang.org/genproto/googleapis/api v0.0.0-20240826202546-f6391c0de4c7
	google.golang.org/genproto/googleapis/rpc => google.golang.org/genproto/googleapis/rpc v0.0.0-20240826202546-f6391c0de4c7
	golang.org/x/crypto => golang.org/x/crypto v0.33.0
)