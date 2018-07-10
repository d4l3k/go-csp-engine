# go-csp-engine [![GoDoc](https://godoc.org/github.com/d4l3k/go-csp-engine?status.svg)](https://godoc.org/github.com/d4l3k/go-csp-engine) [![Build Status](https://travis-ci.com/d4l3k/go-csp-engine.svg?branch=master)](https://travis-ci.com/d4l3k/go-csp-engine)

Content Security Policy engine for Go/Golang. Unit test your CSP rules!

This allows you to check HTML and CSS for preflight CSP violations.

Features:

* Checks script, img, audio, video, track, iframe, object, embed, applet, style,
  base tags.
* Checks `link` tags for stylesheet, prefetch, prerender, and manifest types.
* Checks unsafe inline style and script tags for nonce & hash.
* Check stylesheet @import and @font-face external URLs.

Known limitations:

* Doesn't fetch imported/referenced URLs to check for post flight violations.
  Thus, it doesn't check that the imported external resources have valid hashes.
* Doesn't check stylesheet declarations that access resources like
  `background-image`.
* Doesn't check any network requests made by javascript.

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

## License

go-csp-engine is licensed under the MIT license. See LICENSE file for more
information.
