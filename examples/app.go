package main

import (
	"log"
	"time"

	csrf "github.com/joeirimpan/fastglue-csrf"
	"github.com/valyala/fasthttp"
	"github.com/zerodha/fastglue"
)

func main() {
	testServer := fastglue.NewGlue()
	shutDownCh := make(chan struct{})
	s := &fasthttp.Server{
		Name:                 "test-server",
		ReadTimeout:          5 * time.Second,
		WriteTimeout:         5 * time.Second,
		MaxKeepaliveDuration: 100 * time.Second,
		MaxRequestBodySize:   512000,
		ReadBufferSize:       512000,
	}

	csrf := csrf.New(csrf.Config{
		AuthKey: []byte(`12345678901234567890123456789012`),
		Name:    "custom_csrf",
		MaxAge:  100,
		Path:    "/",
	})

	testServer.GET("/get", csrf.Inject(handlerGetSample))
	testServer.POST("/post", csrf.Protect(handlerPostSample))

	go func() {
		if err := testServer.ListenServeAndWaitGracefully(":8888", "", s, shutDownCh); err != nil {
			log.Fatalf("error starting server: %v", err)
		}
	}()
}

func handlerGetSample(r *fastglue.Request) error {
	return r.SendEnvelope(map[string]string{
		"csrf": r.RequestCtx.UserValue("custom_csrf").(string),
	})
}

func handlerPostSample(r *fastglue.Request) error {
	return r.SendEnvelope("success")
}
