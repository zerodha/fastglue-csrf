# fastglue-csrf

## Overview [![Zerodha Tech](https://zerodha.tech/static/images/github-badge.svg)](https://zerodha.tech)

fastglue-csrf implements CSRF middleware for [fastglue](https://github.com/zerodha/fastglue). 


## Install

```
go get github.com/joeirimpan/fastglue-csrf
```

## Usage

### Short
```golang
g := fastglue.NewGlue()
csrf := csrf.New(csrf.Config{
	AuthKey: []byte(`12345678901234567890123456789012`), // random 32 length key for encrypting
	Name:    "custom_csrf",
	MaxAge:  100,
	Path:    "/",
})
g.GET("/get", csrf.Inject(handlerGetSample))
g.POST("/post", csrf.Protect(handlerPostSample))
```

### Long
```golang
package main

import (
	"log"
	"time"

	"github.com/joeirimpan/fastglue-csrf"
	"github.com/valyala/fasthttp"
	"github.com/zerodha/fastglue"
)

func main() {
	g := fastglue.NewGlue()
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

	g.GET("/get", csrf.Inject(handlerGetSample))
	g.POST("/post", csrf.Protect(handlerPostSample))

	go func() {
		if err := g.ListenServeAndWaitGracefully(":8888", "", s, shutDownCh); err != nil {
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
```

## References

* [gorilla/csrf](https://github.com/gorilla/csrf) implementation for all frameworks implementing `http.Handler`