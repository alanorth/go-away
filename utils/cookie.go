package utils

import (
	"net"
	"net/http"
	"time"
)

var DefaultCookiePrefix = ".go-away-"

// getValidHost Gets a valid host for an http.Cookie Domain field
// TODO: bug: does not work with IPv6, see https://github.com/golang/go/issues/65521
func getValidHost(host string) string {
	ipStr, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return ipStr
}

func SetCookie(name, value string, expiry time.Time, w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Expires:  expiry,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Domain:   getValidHost(r.Host),
	})
}

func ClearCookie(name string, w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
		Domain:   getValidHost(r.Host),
	})
}
