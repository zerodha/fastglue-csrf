package csrf

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/valyala/fasthttp"
	"github.com/zerodha/fastglue"
)

// CSRF consts
const (
	CSRFCookieName   = "csrf"
	CSRFTokenLength  = 32
	CSRFCookieMaxAge = 3600 * 12
)

type tokenCookie struct {
	Token []byte
}

type CSRF struct {
	sc *securecookie.SecureCookie

	cfg Config
}

// New returns a new instance of `CSRF` with securecookie store.
func New(cfg Config) CSRF {
	if cfg.Name == "" {
		cfg.Name = CSRFCookieName
	}

	if cfg.MaxAge == 0 {
		cfg.MaxAge = CSRFCookieMaxAge
	}

	sc := securecookie.New(cfg.AuthKey, nil)
	sc.MaxAge(cfg.MaxAge)

	return CSRF{
		sc:  sc,
		cfg: cfg,
	}
}

// Inject injects csrf token to the GET handlers
func (c *CSRF) Inject(handler fastglue.FastRequestHandler) fastglue.FastRequestHandler {
	return func(r *fastglue.Request) error {
		// Generate token
		tk, err := generateRandomString(CSRFTokenLength)
		if err != nil {
			c.deny(r)
			return nil
		}

		// Encode and set the cookie in the header
		value, err := c.sc.Encode(c.cfg.Name, tokenCookie{Token: tk})
		if err != nil {
			c.deny(r)
			return err
		}

		cookie := &http.Cookie{
			Name:     c.cfg.Name,
			Value:    value,
			MaxAge:   c.cfg.MaxAge,
			Path:     c.cfg.Path,
			Secure:   !c.cfg.Unsecure,
			HttpOnly: true,
			SameSite: http.SameSite(c.cfg.SameSite),
			Domain:   c.cfg.Domain,
		}

		if c.cfg.MaxAge > 0 {
			cookie.Expires = time.Now().Add(
				time.Duration(c.cfg.MaxAge) * time.Second)
		}

		if err = setCookie(cookie, r); err != nil {
			c.deny(r)
			return err
		}

		// Mask csrf token
		maskedTk, err := c.mask(tk)
		if err != nil {
			c.deny(r)
			return err
		}

		r.RequestCtx.SetUserValue(c.cfg.Name, maskedTk)

		return handler(r)
	}
}

// Protect checks if the Set-Cookie headers from the GET request is same as the one from form values.
func (c *CSRF) Protect(handler fastglue.FastRequestHandler) fastglue.FastRequestHandler {
	return func(r *fastglue.Request) error {
		var (
			csrfCookie = r.RequestCtx.Request.Header.Cookie(c.cfg.Name)

			decoded tokenCookie
		)

		// Decode the cookie
		if err := c.sc.Decode(c.cfg.Name, string(csrfCookie), &decoded); err != nil || len(decoded.Token) != CSRFTokenLength {
			c.deny(r)
			return err
		}

		// Validations
		if decoded.Token == nil {
			c.deny(r)
			return fmt.Errorf("invalid decoded token")
		}

		// Get csrf token from the form, unmask the token
		xcsrfToken := string(r.RequestCtx.FormValue(c.cfg.Name))

		issued, err := base64.StdEncoding.DecodeString(xcsrfToken)
		if err != nil {
			c.deny(r)
			return err
		}

		requestToken := c.unmask(issued)

		if !compareTokens(requestToken, decoded.Token) {
			c.deny(r)
			return fmt.Errorf("token mismatch")
		}

		// disable caching
		r.RequestCtx.Response.Header.Add("Vary", "Cookie")

		return handler(r)
	}
}

// deny clears the cookie and sets the status_code to forbidden.
func (c *CSRF) deny(r *fastglue.Request) {
	// 1. clear cookie
	// 2. Set forbidden status
	setCookie(&http.Cookie{ //nolint
		Name:     c.cfg.Name,
		Value:    "",
		Expires:  fasthttp.CookieExpireDelete,
		Path:     "/",
		Secure:   !c.cfg.Unsecure,
		HttpOnly: true,
	}, r)

	r.RequestCtx.SetStatusCode(fasthttp.StatusForbidden)
}

// mask adds a OTP to the original token.
func (c *CSRF) mask(realToken []byte) (string, error) {
	otp, err := generateRandomString(CSRFTokenLength)
	if err != nil {
		return "", err
	}

	// XOR the OTP with the real token to generate a masked token. Append the
	// OTP to the front of the masked token to allow unmasking in the subsequent
	// request.
	return base64.StdEncoding.EncodeToString(append(otp, xorToken(otp, realToken)...)), nil
}

// unmask splits the issued token (one-time-pad + masked token) and returns the
// unmasked request token for comparison.
func (c *CSRF) unmask(issued []byte) []byte {
	// Issued tokens are always masked and combined with the pad.
	if len(issued) != CSRFTokenLength*2 {
		return nil
	}

	// We now know the length of the byte slice.
	var (
		otp    = issued[CSRFTokenLength:]
		masked = issued[:CSRFTokenLength]
	)

	// Unmask the token by XOR'ing it against the OTP used to mask it.
	return xorToken(otp, masked)
}

// xorToken XORs tokens ([]byte) to provide unique-per-request CSRF tokens. It
// will return a masked token if the base token is XOR'ed with a one-time-pad.
// An unmasked token will be returned if a masked token is XOR'ed with the
// one-time-pad used to mask it.
func xorToken(a, b []byte) []byte {
	var n = len(a)

	if len(b) < n {
		n = len(b)
	}

	res := make([]byte, n)

	for i := 0; i < n; i++ {
		res[i] = a[i] ^ b[i]
	}

	return res
}

// compare securely (constant-time) compares the unmasked token from the request
// against the real token from the session.
func compareTokens(a, b []byte) bool {
	// This is required as subtle.ConstantTimeCompare does not check for equal
	// lengths in Go versions prior to 1.3.
	if len(a) != len(b) {
		return false
	}

	return subtle.ConstantTimeCompare(a, b) == 1
}
