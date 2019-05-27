package csp

import (
	"net/url"
	"strings"

	"github.com/gobwas/glob"
	"github.com/pkg/errors"
)

// Policy represents the entire CSP policy and its directives.
type Policy struct {
	Directives              map[string]Directive
	UpgradeInsecureRequests bool
	BlockAllMixedContent    bool
}

// ParsePolicy parses all the directives in a CSP policy.
func ParsePolicy(policy string) (Policy, error) {
	p := Policy{
		Directives: map[string]Directive{},
	}
	directiveDefs := strings.Split(policy, ";")
	for _, directive := range directiveDefs {
		fields := strings.Fields(directive)
		if len(fields) == 0 {
			return Policy{}, errors.Errorf("empty directive field")
		}
		directiveType := fields[0]
		switch directiveType {
		case "base-uri", "child-src", "connect-src", "default-src", "font-src", "form-action", "frame-ancestors", "frame-src", "img-src", "manifest-src", "media-src", "object-src", "script-src", "style-src", "worker-src":
			d, err := ParseSourceDirective(fields[1:])
			if err != nil {
				return Policy{}, err
			}
			p.Directives[directiveType] = d

		case "report-uri":
			if len(fields) != 2 {
				return Policy{}, errors.Errorf("report-uri expects 1 field; got %q", directive)
			}
			if _, err := url.Parse(fields[1]); err != nil {
				return Policy{}, err
			}

		case "upgrade-insecure-requests":
			if len(fields) != 1 {
				return Policy{}, errors.Errorf("upgrade-insecure-requests expects 0 field; got %q", directive)
			}
			p.UpgradeInsecureRequests = true

		case "block-all-mixed-content":
			if len(fields) != 1 {
				return Policy{}, errors.Errorf("block-all-mixed-content expects 0 field; got %q", directive)
			}
			p.BlockAllMixedContent = true

		default:
			return Policy{}, errors.Errorf("unknown directive %q", directive)
		}
	}

	return p, nil
}

// Directive returns the first directive that exists in the order: directive
// with the provided name, default-src, and finally 'none' directive.
func (p Policy) Directive(name string) Directive {
	d, ok := p.Directives[name]
	if ok {
		return d
	}

	// frame-ancestors defaults to always allow.
	if name == "frame-ancestors" {
		return AllowDirective{}
	}

	d, ok = p.Directives["default-src"]
	if ok {
		return d
	}

	// If no directives use default policy.
	g, err := glob.Compile("*://*")
	if err != nil {
		panic(err)
	}
	return SourceDirective{
		Hosts: []glob.Glob{g},
	}
}
