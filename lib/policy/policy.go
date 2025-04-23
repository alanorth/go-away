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

func NewPolicy(r io.Reader, snippetsDirectory string) (*Policy, error) {
	var p Policy
	p.Networks = make(map[string][]Network)
	p.Conditions = make(map[string][]string)
	p.Challenges = make(map[string]Challenge)

	if snippetsDirectory == "" {
		err := yaml.NewDecoder(r).Decode(&p)
		if err != nil {
			return nil, err
		}
	} else {
		err := yaml.NewDecoder(r, yaml.ReferenceDirs(snippetsDirectory)).Decode(&p)
		if err != nil {
			return nil, err
		}

		// add specific entries from snippets
		entries, err := os.ReadDir(snippetsDirectory)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			var entryPolicy Policy
			if !entry.IsDir() {
				entryData, err := os.ReadFile(path.Join(snippetsDirectory, entry.Name()))
				if err != nil {
					return nil, err
				}
				err = yaml.NewDecoder(bytes.NewReader(entryData), yaml.ReferenceDirs(snippetsDirectory)).Decode(&entryPolicy)
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
	}
	return &p, nil
}
