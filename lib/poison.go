package lib

import (
	"git.gammaspectra.live/git/go-away/embed"
	"io"
	"path"
	"slices"
	"strings"
)

var poisonEncodings = []string{"br", "zstd", "gzip"}

func (state *State) getPoison(mime string, encodings []string) (r io.ReadCloser, encoding string) {
	for _, encoding = range poisonEncodings {
		if !slices.Contains(encodings, encoding) {
			continue
		}

		p := path.Join("poison", strings.ReplaceAll(mime, "/", "_")+"."+encoding+".poison")
		f, err := embed.PoisonFs.Open(p)
		if err == nil {
			return f, encoding
		}
	}
	return nil, ""
}
