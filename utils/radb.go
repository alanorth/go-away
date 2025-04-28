package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type RADb struct {
	target string
	dialer net.Dialer
}

const RADBServer = "whois.radb.net:43"

func NewRADb() (*RADb, error) {

	host, port, err := net.SplitHostPort(RADBServer)
	if err != nil {
		return nil, err
	}

	return &RADb{
		target: fmt.Sprintf("%s:%s", host, port),
		dialer: net.Dialer{
			Timeout: 5 * time.Second,
		},
	}, nil
}

var whoisRouteRegex = regexp.MustCompile("(?P<prefix>(([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)|([0-9a-f:]+::))/[0-9]+)")

func (db *RADb) query(fn func(n int, record []byte) error, queries ...string) error {

	conn, err := db.dialer.Dial("tcp", db.target)
	if err != nil {
		return err
	}
	defer conn.Close()

	if len(queries) > 1 {
		// enable persistent conn
		_ = conn.SetDeadline(time.Now().Add(time.Second * 5))
		_, err = conn.Write([]byte("!!\n"))
		if err != nil {
			return err
		}
	}

	scanner := bufio.NewScanner(conn)
	scanner.Split(bufio.ScanLines)
	// 16 MiB lines
	const bufferSize = 1024 * 1024 * 16
	scanner.Buffer(make([]byte, 0, bufferSize), bufferSize)

	for _, q := range queries {

		_ = conn.SetDeadline(time.Now().Add(time.Second * 5))
		_, err = conn.Write([]byte(strings.TrimSpace(q) + "\n"))
		if err != nil {
			return err
		}

		n := 0

		for scanner.Scan() {
			buf := bytes.Trim(scanner.Bytes(), "\r\n")
			if bytes.HasPrefix(buf, []byte("%")) || bytes.Equal(buf, []byte("C")) {
				// end of record
				break
			}
			err = fn(n, buf)
			if err != nil {
				return err
			}
			n++
		}

		if scanner.Err() != nil {
			return scanner.Err()
		}
	}

	if len(queries) > 1 {
		// exit
		_ = conn.SetDeadline(time.Now().Add(time.Second * 5))
		_, err = conn.Write([]byte("q\n"))
		if err != nil {
			return err
		}
	}

	return nil
}

func (db *RADb) FetchIPInfo(ip net.IP) (result []string, err error) {
	var ipNet net.IPNet
	if ip4 := ip.To4(); ip4 != nil {
		ipNet = net.IPNet{
			IP: ip4,
			// single ip
			Mask: net.CIDRMask(len(ip4)*8, len(ip4)*8),
		}
	} else {
		ipNet = net.IPNet{
			IP: ip,
			// single ip
			Mask: net.CIDRMask(len(ip)*8, len(ip)*8),
		}
	}

	err = db.query(func(n int, record []byte) error {
		result = append(result, string(record))
		return nil
	}, fmt.Sprintf("!r%s,l", ipNet.String()))

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (db *RADb) FetchASNets(asn int) (result []net.IPNet, err error) {

	ix := whoisRouteRegex.SubexpIndex("prefix")
	if ix == -1 {
		panic("invalid regex prefix")
	}

	var data []byte

	err = db.query(func(n int, record []byte) error {
		if n == 0 {
			// do not append ASN number reply
			return nil
		}
		// pad data
		if n == 1 {
			data = append(data, ' ')
		}
		data = append(data, record...)
		return nil
	},
		// See https://www.radb.net/query/help
		// fetch IPv4 routes
		fmt.Sprintf("!gas%d", asn),
		// fetch IPv6 routes
		fmt.Sprintf("!6as%d", asn),
	)
	if err != nil {
		return nil, err
	}

	matches := whoisRouteRegex.FindAllSubmatch(data, -1)
	for _, match := range matches {
		_, ipNet, err := net.ParseCIDR(string(match[ix]))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", string(match[ix]), err)
		}
		result = append(result, *ipNet)
	}

	return result, nil
}
