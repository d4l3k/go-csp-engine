# go-csp-engine [![GoDoc](https://godoc.org/github.com/d4l3k/go-csp-engine?status.svg)](https://godoc.org/github.com/d4l3k/go-csp-engine) [![Build Status](https://travis-ci.com/d4l3k/go-csp-engine.svg?branch=master)](https://travis-ci.com/d4l3k/go-csp-engine)

Content Security Policy engine for Go/Golang. Unit test your CSP rules!

## Example

```go
package main

import (
	"net/url"
	"strings"
  "log"

	csp "github.com/d4l3k/go-csp-engine"
)

func main() {
  policy, err := csp.ParsePolicy("default-src: 'self'; script-src: 'nonce-foo'; img-src https://cdn")
  if err != nil {
    log.Fatal(err)
  }
  page, err := url.Parse('http://example.com/bar/')
  if err != nil {
    log.Fatal(err)
  }
  valid, reports, err := csp.ValidatePage(policy, *page, strings.NewReader(`
    <link rel="stylesheet" href="./foo.css">
    <script nonce="foo">alert('boo yeah!')</script>
    <img src="https://cdn/blah">
  `))
  if err != nil {
    log.Fatal(err)
  }
  log.Println(valid, reports)
}
```

