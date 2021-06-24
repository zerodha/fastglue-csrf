package gluecsrf

import (
	"crypto/rand"
	"fmt"
	"net/http"

	"github.com/valyala/fasthttp"
	"github.com/zerodha/fastglue"
)

const (
	randomString = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// setCookie implements the cookie interface.
func setCookie(cookie *http.Cookie, w interface{}) error {
	req, ok := w.(*fastglue.Request)
	if !ok {
		return fmt.Errorf("invalid param for w")
	}

	// Acquire cookie
	fck := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(fck)
	fck.SetKey(cookie.Name)
	fck.SetValue(cookie.Value)
	fck.SetMaxAge(cookie.MaxAge)
	fck.SetPath(cookie.Path)
	fck.SetSecure(cookie.Secure)
	fck.SetHTTPOnly(cookie.HttpOnly)
	fck.SetSameSite(fasthttp.CookieSameSite(cookie.SameSite))
	fck.SetDomain(cookie.Domain)
	fck.SetExpire(cookie.Expires)

	req.RequestCtx.Response.Header.SetCookie(fck)

	return nil
}

// generateRandomString generates a cryptographically random,
// alphanumeric string of length n.
func generateRandomString(n int) (string, error) {
	var bytes = make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for k, v := range bytes {
		bytes[k] = randomString[v%byte(len(randomString))]
	}

	return string(bytes), nil
}
