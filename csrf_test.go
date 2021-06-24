package csrf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/zerodha/fastglue"
)

var (
	testServer     *fastglue.Fastglue
	shutDownCh     chan struct{}
	testHTTPClient *http.Client
)

func setupTest() {
	jar, _ := cookiejar.New(nil)

	testHTTPClient = &http.Client{Jar: jar}

	testServer = fastglue.NewGlue()
	shutDownCh = make(chan struct{})
	s := &fasthttp.Server{
		Name:                 "test-server",
		ReadTimeout:          5 * time.Second,
		WriteTimeout:         5 * time.Second,
		MaxKeepaliveDuration: 100 * time.Second,
		MaxRequestBodySize:   512000,
		ReadBufferSize:       512000,
	}

	sampleKey, _ := generateRandomString(32)

	csrf := New(Config{
		AuthKey: []byte(sampleKey),
		Name:    "custom_csrf",
		MaxAge:  100,
		Path:    "/",
	})

	testServer.GET("/get", csrf.Inject(handlerGetSample))
	testServer.POST("/post", csrf.Protect(handlerPostSample))

	go testServer.ListenServeAndWaitGracefully(":8888", "", s, shutDownCh)
}

func teardownTest() {
	shutDownCh <- struct{}{}
}

func TestMain(m *testing.M) {
	setupTest()
	code := m.Run()
	teardownTest()
	os.Exit(code)
}

func TestCSRF(t *testing.T) {
	// GET request handler injects set-cookie header and return a masked csrf token
	resp, err := doTestRequest("GET", "/get", url.Values{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	var ck *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "custom_csrf" {
			ck = c
			break
		}
	}

	data, _ := ioutil.ReadAll(resp.Body)
	var r fastglue.Envelope
	json.Unmarshal(data, &r)

	assert.Contains(t, ck.Path, "/", "cookie path should be `/`")

	// POST request should go through only if the correct csrf token, cookie header exist
	v := url.Values{}
	v.Add("custom_csrf", r.Data.(map[string]interface{})["csrf"].(string))

	h := http.Header{}
	h.Add("Cookie", resp.Header.Get("Set-Cookie"))
	resp, err = doTestRequest("POST", "/post", v, h)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, resp.StatusCode, http.StatusOK, "status code should be 200")
}

func handlerGetSample(r *fastglue.Request) error {
	return r.SendEnvelope(map[string]string{
		"csrf": r.RequestCtx.UserValue("custom_csrf").(string),
	})
}

func handlerPostSample(r *fastglue.Request) error {
	return r.SendEnvelope("success")
}

func doTestRequest(method, url string, params url.Values, headers http.Header) (*http.Response, error) {
	var (
		postBody io.Reader
		reqBody  = []byte(params.Encode())
	)

	// Encode POST / PUT params.
	if method == fasthttp.MethodPost || method == fasthttp.MethodPut {
		postBody = bytes.NewReader(reqBody)
	}

	req, err := http.NewRequest(method, "http://localhost:8888"+url, postBody)
	if err != nil {
		return nil, fmt.Errorf("Error forming batch alert request: %v", err)
	}

	if method == fasthttp.MethodPost || method == fasthttp.MethodPut {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// If the request method is GET or DELETE, add the params as QueryString.
	if method == fasthttp.MethodGet || method == fasthttp.MethodDelete {
		req.URL.RawQuery = string(reqBody)
	}

	for k, v := range headers {
		req.Header.Add(k, v[0])
	}

	resp, err := testHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error performing batch alert request: %v", err)
	}

	return resp, nil
}
