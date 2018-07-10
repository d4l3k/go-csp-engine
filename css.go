package csp

import (
	"log"
	"net/url"
	"strings"

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

// ValidateStylesheet validates a stylesheet for CSP violations from imports and
// font-face sources.
func ValidateStylesheet(p Policy, page url.URL, css string) (bool, []Report, error) {
	log.Printf("validate stylesheet %q", css)
	stylesheet, err := parser.Parse(css)
	if err != nil {
		return false, nil, err
	}

	directiveName := "style-src"
	directive := p.Directive(directiveName)

	directiveFontName := "font-src"
	directiveFont := p.Directive(directiveFontName)

	var reports []Report
	for _, rule := range stylesheet.Rules {
		if rule.Name == "@import" {
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
		} else if rule.Name == "@font-face" {
			for _, decl := range rule.Declarations {
				if decl.Property != "src" {
					continue
				}
				parts := strings.Split(decl.Value, ",")
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(part, "local(") {
						continue
					}

					fields := strings.Fields(part)
					imp, err := parseCSSURL(fields[0])
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

					v, err := directiveFont.Check(ctx)
					if err != nil {
						return false, nil, err
					}
					log.Printf("%+v; %+v; %+v", v, ctx, directiveFont)
					if !v {
						reports = append(reports, ctx.Report(directiveFontName, directiveFont, ctx))
					}
				}
			}
		}
	}
	return len(reports) == 0, reports, nil
}
