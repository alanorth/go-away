package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itchyny/gojq"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
)

type Network struct {
	Url  *string `yaml:"url,omitempty"`
	File *string `yaml:"file,omitempty"`

	JqPath *string `yaml:"jq-path,omitempty"`
	Regex  *string `yaml:"regex,omitempty"`

	Prefixes []string `yaml:"prefixes,omitempty"`
}

func (n Network) FetchPrefixes(c *http.Client) (output []net.IPNet, err error) {
	if len(n.Prefixes) > 0 {
		for _, prefix := range n.Prefixes {
			ipNet, err := parseCIDROrIP(prefix)
			if err != nil {
				return nil, err
			}
			output = append(output, ipNet)
		}
	}

	var reader io.Reader
	if n.Url != nil {
		response, err := c.Get(*n.Url)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
		}
		reader = response.Body
	} else if n.File != nil {
		file, err := os.Open(*n.File)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	} else {
		if len(output) > 0 {
			return output, nil
		}
		return nil, errors.New("no url, file or prefixes specified")
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	if n.JqPath != nil {
		var jsonData any
		err = json.Unmarshal(data, &jsonData)
		if err != nil {
			return nil, err
		}

		query, err := gojq.Parse(*n.JqPath)
		if err != nil {
			return nil, err
		}
		iter := query.Run(jsonData)
		for {
			value, more := iter.Next()
			if !more {
				break
			}

			if strValue, ok := value.(string); ok {
				ipNet, err := parseCIDROrIP(strValue)
				if err != nil {
					return nil, err
				}
				output = append(output, ipNet)
			} else {
				return nil, fmt.Errorf("invalid value from jq-query: %v", value)
			}
		}
		return output, nil
	} else if n.Regex != nil {
		expr, err := regexp.Compile(*n.Regex)
		if err != nil {
			return nil, err
		}
		prefixName := expr.SubexpIndex("prefix")
		if prefixName == -1 {
			return nil, fmt.Errorf("invalid regex %q: could not find prefix named match", *n.Regex)
		}
		matches := expr.FindAllSubmatch(data, -1)
		for _, match := range matches {
			matchName := string(match[prefixName])
			ipNet, err := parseCIDROrIP(matchName)
			if err != nil {
				return nil, err
			}
			output = append(output, ipNet)
		}
	} else {
		return nil, errors.New("no jq-path or regex specified")
	}
	return output, nil
}
