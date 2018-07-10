package csp

import (
	"io"
	"log"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/aymerick/douceur/parser"
	"github.com/pkg/errors"
)

// see https://developer.mozilla.org/en-US/docs/Web/CSS/url
var urlFormats = []struct {
	prefix, suffix string
}{
	{`url("`, `")`},
	{`url('`, `')`},
	{`url(`, `)`},
	{`"`, `"`},
	{`'`, `'`},
}

func parseCSSURL(s string) (string, error) {
	for _, format := range urlFormats {
		if strings.HasPrefix(s, format.prefix) && strings.HasSuffix(s, format.suffix) {
			return s[len(format.prefix) : len(s)-len(format.suffix)], nil
		}
	}
	return "", errors.Errorf("invalid URL or string: %q", s)
}

func ValidateStylesheet(p Policy, page url.URL, css string) (bool, []Report, error) {
	log.Printf("validate stylesheet %q", css)
	stylesheet, err := parser.Parse(css)
	if err != nil {
		return false, nil, err
	}

	directiveName := "style-src"
	directive := p.Directive(directiveName)

	var reports []Report
	for _, rule := range stylesheet.Rules {
		if rule.Name != "@import" {
			continue
		}
		parts := strings.Fields(rule.Prelude)
		if len(parts) == 0 {
			return false, nil, errors.Errorf("@import empty")
		}
		imp, err := parseCSSURL(parts[0])
		if err != nil {
			return false, nil, err
		}
		log.Println(imp)
		ctx := SourceContext{
			Page: page,
		}
		parsed, err := url.Parse(imp)
		if err != nil {
			return false, nil, err
		}

		ctx.URL = *page.ResolveReference(parsed)

		v, err := directive.Check(ctx)
		if err != nil {
			return false, nil, err
		}
		log.Printf("%+v; %+v; %+v", v, ctx, directive)
		if !v {
			reports = append(reports, ctx.Report(directiveName, directive, ctx))
		}
	}
	return len(reports) == 0, reports, nil
}

// ValidatePage checks that an HTML page passes the specified CSP policy.
func ValidatePage(p Policy, page url.URL, html io.Reader) (bool, []Report, error) {
	doc, err := goquery.NewDocumentFromReader(html)
	if err != nil {
		return false, nil, err
	}
	var reports []Report

	srcTypes := map[string]string{
		"script-src": "script",
		"img-src":    "img",
		"media-src":  "audio, video, track",
		"frame-src":  "iframe",
		"object-src": "object, embed, applet",
		"style-src":  "style",
	}
	for directiveName, elems := range srcTypes {
		directive := p.Directive(directiveName)
		var err2 error
		doc.Find(elems).Each(func(i int, s *goquery.Selection) {
			ctx := SourceContext{
				Page:  page,
				Nonce: s.AttrOr("nonce", ""),
			}
			src := s.AttrOr("src", "")
			if len(src) > 0 {
				parsed, err := url.Parse(src)
				if err != nil {
					err2 = err
					return
				}

				ctx.URL = *page.ResolveReference(parsed)
			} else {
				ctx.Body = []byte(s.Text())
				ctx.UnsafeInline = true
			}

			v, err := directive.Check(ctx)
			if err != nil {
				err2 = err
				return
			}
			if !v {
				reports = append(reports, ctx.Report(directiveName, directive, ctx))
			}

			if goquery.NodeName(s) == "style" {
				_, reportsCSS, err := ValidateStylesheet(p, page, s.Text())
				if err != nil {
					err2 = err
					return
				}
				reports = append(reports, reportsCSS...)
			}
		})
		if err2 != nil {
			return false, nil, err2
		}
	}

	hrefTypes := map[string]string{
		"base-uri":     "base",
		"style-src":    "link[rel=stylesheet]",
		"prefetch-src": "link[rel=prefetch], link[rel=prerender]",
		"manifest-src": "link[rel=manifest]",
	}
	for directiveName, elems := range hrefTypes {
		directive := p.Directive(directiveName)
		var err2 error
		doc.Find(elems).Each(func(i int, s *goquery.Selection) {
			ctx := SourceContext{
				Page:  page,
				Nonce: s.AttrOr("nonce", ""),
			}
			href := s.AttrOr("href", "")
			if len(href) > 0 {
				parsed, err := url.Parse(href)
				if err != nil {
					err2 = err
					return
				}
				ctx.URL = *page.ResolveReference(parsed)
			}

			v, err := directive.Check(ctx)
			if err != nil {
				err2 = err
				return
			}
			if !v {
				reports = append(reports, ctx.Report(directiveName, directive, ctx))
			}
		})
		if err2 != nil {
			return false, nil, err2
		}
	}

	return len(reports) == 0, reports, nil
}
