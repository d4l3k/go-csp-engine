package csp

import (
	"io"
	"net/url"

	"github.com/PuerkitoBio/goquery"
)

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
