package policy

import (
	"errors"
	"fmt"
	"net"
)

func parseCIDROrIP(value string) (net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(value)
	if err != nil {
		ip := net.ParseIP(value)
		if ip == nil {
			return net.IPNet{}, fmt.Errorf("failed to parse CIDR: %s", err)
		}

		if ip4 := ip.To4(); ip4 != nil {
			return net.IPNet{
				IP: ip4,
				// single ip
				Mask: net.CIDRMask(len(ip4)*8, len(ip4)*8),
			}, nil
		}
		return net.IPNet{
			IP: ip,
			// single ip
			Mask: net.CIDRMask(len(ip)*8, len(ip)*8),
		}, nil
	} else if ipNet != nil {
		return *ipNet, nil
	} else {
		return net.IPNet{}, errors.New("invalid CIDR")
	}
}

type Policy struct {

	// Networks map of networks and prefixes to be loaded
	Networks map[string][]Network `yaml:"networks"`

	Conditions map[string][]string `yaml:"conditions"`

	Challenges map[string]Challenge `yaml:"challenges"`

	Rules []Rule `yaml:"rules"`
}
