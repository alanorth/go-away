package policy

import (
	"bytes"
	"github.com/goccy/go-yaml"
	"io"
	"os"
	"path"
)

type Policy struct {

	// Networks map of networks and prefixes to be loaded
	Networks map[string][]Network `yaml:"networks"`

	Conditions map[string][]string `yaml:"conditions"`

	Challenges map[string]Challenge `yaml:"challenges"`

	Rules []Rule `yaml:"rules"`
}

func NewPolicy(r io.Reader, snippetsDirectories ...string) (*Policy, error) {
	var p Policy
	p.Networks = make(map[string][]Network)
	p.Conditions = make(map[string][]string)
	p.Challenges = make(map[string]Challenge)

	if len(snippetsDirectories) == 0 {
		err := yaml.NewDecoder(r).Decode(&p)
		if err != nil {
			return nil, err
		}
	} else {
		var entries []string
		for _, dir := range snippetsDirectories {
			if dir == "" {
				// skip nil directories
				continue
			}
			dirFiles, err := os.ReadDir(dir)
			if err != nil {
				return nil, err
			}
			for _, file := range dirFiles {
				if file.IsDir() {
					continue
				}
				entries = append(entries, path.Join(dir, file.Name()))
			}
		}

		err := yaml.NewDecoder(r, yaml.ReferenceFiles(entries...)).Decode(&p)
		if err != nil {
			return nil, err
		}

		// add specific entries from snippets
		for _, entry := range entries {
			var entryPolicy Policy
			entryData, err := os.ReadFile(entry)
			if err != nil {
				return nil, err
			}
			err = yaml.NewDecoder(bytes.NewReader(entryData), yaml.ReferenceFiles(entries...)).Decode(&entryPolicy)
			if err != nil {
				return nil, err
			}

			// add networks / conditions / challenges definitions if they don't exist already

			for k, v := range entryPolicy.Networks {
				// add network if policy entry does not exist
				_, ok := p.Networks[k]
				if !ok {
					p.Networks[k] = v
				}
			}

			for k, v := range entryPolicy.Conditions {
				// add condition if policy entry does not exist
				_, ok := p.Conditions[k]
				if !ok {
					p.Conditions[k] = v
				}
			}

			for k, v := range entryPolicy.Challenges {
				// add challenge if policy entry does not exist
				_, ok := p.Challenges[k]
				if !ok {
					p.Challenges[k] = v
				}
			}
		}
	}
	return &p, nil
}
