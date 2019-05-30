package csp

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func checkErr(t *testing.T, got error, want string) {
	if got == nil && want == "" {
		return
	} else if got != nil && want == "" {
		t.Fatalf("unexpected error %+v", got)
	} else if got == nil && want != "" {
		t.Fatalf("expected error matching %q", want)
	}

	if !strings.Contains(got.Error(), want) {
		t.Fatalf("expected error matching %q; got %+v", want, got)
	}
}

type testCase struct {
	name                   string
	policy                 string
	page                   string
	html                   string
	valid                  bool
	policyErr, validateErr string
}

func TestCSP(t *testing.T) {
	t.Parallel()

	cases := []testCase{
		{
			policy: "default-src 'self'",
			page:   "https://google.com",
			html:   `<script src="https://google.com"></script>`,
			valid:  true,
		},
		{
			policy: "default-src 'none'",
			page:   "https://google.com",
			html:   `<script src="https://google.com"></script>`,
			valid:  false,
		},
		{
			policy: "script-src *; default-src 'none'",
			page:   "https://google.com",
			html:   `<script src="https://google.com"></script>`,
			valid:  true,
		},
		{
			policy: "default-src http:",
			page:   "https://google.com",
			html:   `<script src="https://google.com"></script>`,
			valid:  true,
		},
		{
			policy: "default-src google.com",
			page:   "https://google.com",
			html:   `<script src="https://google.com"></script>`,
			valid:  true,
		},
		{
			policy: "default-src *.google.com",
			page:   "https://google.com",
			html:   `<script src="https://www.google.com"></script>`,
			valid:  true,
		},
		{
			policy: "default-src 'nonce-foo'",
			page:   "https://google.com",
			html:   `<script src="https://www.google.com"></script>`,
			valid:  false,
		},
		{
			policy: "default-src 'nonce-foo'",
			page:   "https://google.com",
			html:   `<script nonce="foo" src="https://www.google.com"></script>`,
			valid:  true,
		},
		{
			policy: "default-src 'sha256-LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564='",
			page:   "https://google.com",
			html:   `<script>foo</script>`,
			valid:  true,
		},
		{
			policy: "default-src 'sha256-LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564='",
			page:   "https://google.com",
			html:   `<script>bar</script>`,
			valid:  false,
		},
		{
			policy: "default-src 'unsafe-inline'",
			page:   "https://google.com",
			html:   `<script>bar</script>`,
			valid:  true,
		},
		{
			policy: "style-src 'unsafe-inline'",
			page:   "https://google.com",
			html:   `<style>bar</style>`,
			valid:  true,
		},
		{
			policy: "style-src 'none",
			page:   "https://google.com",
			html:   `<style>bar</style>`,
			valid:  false,
		},
		{
			policy: "style-src https://bar.com",
			page:   "https://google.com",
			html:   `<link rel="stylesheet" href="https://bar.com/style.css">`,
			valid:  true,
		},
		{
			name:   "relative stylesheets",
			policy: "style-src 'self'",
			page:   "https://google.com",
			html:   `<link rel="stylesheet" href="style.css">`,
			valid:  true,
		},
		{
			name:   "parse inline stylesheets for CSS imports",
			policy: "style-src 'unsafe-inline'",
			page:   "https://google.com",
			html:   `<style>@import url('blah.html')</style>`,
			valid:  false,
		},
		{
			policy: "style-src 'unsafe-inline' 'self'",
			page:   "https://google.com",
			html:   `<style>@import url('blah.html')</style>`,
			valid:  true,
		},
		{
			name:   "parse inline stylesheets for @font-face imports",
			policy: "style-src 'unsafe-inline'; font-src 'none'",
			page:   "https://google.com",
			html: `<style>@font-face {
				font-family: "Open Sans";
				src: url("/fonts/OpenSans-Regular-webfont.woff2") format("woff2"),
						 url("/fonts/OpenSans-Regular-webfont.woff") format("woff");
			}</style>`,
			valid: false,
		},
		{
			name:   "parse inline stylesheets for @font-face imports",
			policy: "style-src 'unsafe-inline'; font-src 'self'",
			page:   "https://google.com",
			html: `<style>@font-face {
				font-family: "Open Sans";
				src: local(blah),
				     url("/fonts/OpenSans-Regular-webfont.woff2") format("woff2"),
						 url("/fonts/OpenSans-Regular-webfont.woff") format("woff");
			}</style>`,
			valid: true,
		},
		{
			name:   "unsafe-inline is disabled when nonce is present",
			policy: "default-src 'nonce-foo' 'unsafe-inline'",
			page:   "https://google.com",
			html:   `<script>blah</script>`,
			valid:  false,
		},
		{
			policy: "img-src 'self'",
			page:   "https://google.com",
			html:   `<img src="https://google.com" />`,
			valid:  true,
		},
		{
			policy: "img-src 'self'",
			page:   "https://google.com",
			html:   `<img src="https://blah.com" />`,
			valid:  false,
		},
		{
			policy: "img-src 'self'",
			page:   "https://google.com",
			html:   `<link rel="icon" href="https://blah.com" />`,
			valid:  false,
		},
		{
			policy: "img-src 'self'",
			page:   "https://google.com",
			html:   `<link rel="apple-touch-icon" href="https://blah.com" />`,
			valid:  false,
		},
		{
			name:   "mixed-content img",
			policy: "default-src 'self'",
			page:   "https://google.com",
			html:   `<img src="http://google.com" />`,
			valid:  true,
		},
		{
			name:   "mixed-content script",
			policy: "default-src 'self'",
			page:   "https://google.com",
			html:   `<script src="http://google.com"></script>`,
			valid:  false,
		},
		{
			name:   "upgrade-insecure-requests valid",
			policy: "upgrade-insecure-requests",
			page:   "https://google.com",
			html:   `<img src="http://google.com" />`,
			valid:  true,
		},
		{
			name:   "block-all-mixed-content insecure",
			policy: "block-all-mixed-content",
			page:   "https://google.com",
			html:   `<img src="http://google.com" />`,
			valid:  false,
		},
		{
			name:   "block-all-mixed-content secure",
			policy: "block-all-mixed-content",
			page:   "https://google.com",
			html:   `<img src="https://google.com" />`,
			valid:  true,
		},
		{
			name:   "block-all-mixed-content + upgrade-insecure-requests",
			policy: "block-all-mixed-content; upgrade-insecure-requests",
			page:   "https://google.com",
			html:   `<img src="http://google.com" />`,
			valid:  true,
		},
		{
			name:   "report-uri parses",
			policy: "report-uri https://foo.com",
			page:   "https://bar.com",
			html:   ``,
			valid:  true,
		},
		{
			name:   "default policy allows everything",
			policy: "font-src 'none'",
			page:   "https://bar.com",
			html: `
				<script src="http://foobar.com" />
				<script src="https://foobar.com" />
			`,
			valid: true,
		},
	}

	for i, c := range cases {
		i := i
		c := c
		t.Run(fmt.Sprintf("%d.%s", i, c.name), func(t *testing.T) {
			t.Parallel()

			t.Logf("testCase{%q, %q, %q}", c.policy, c.page, c.html)

			p, err := ParsePolicy(c.policy)
			checkErr(t, err, c.policyErr)
			page, err := url.Parse(c.page)
			if err != nil {
				t.Fatal(err)
			}
			valid, reports, err := ValidatePage(p, *page, strings.NewReader(c.html))
			checkErr(t, err, c.validateErr)
			if valid != c.valid {
				t.Errorf("ValidatePage(...) = %v; not %v; reports = %+v", valid, c.valid, reports)
			}
		})
	}
}
