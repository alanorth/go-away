package lib

import (
	"net/http"
	"time"
)

var CookiePrefix = ".go-away-"

func SetCookie(name, value string, expiry time.Time, w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Expires:  expiry,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}
func ClearCookie(name string, w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
}
