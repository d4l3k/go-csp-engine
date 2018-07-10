package csp

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"net/url"
	"regexp"
	"strings"

	"github.com/gobwas/glob"
	"github.com/pkg/errors"
)

var hostSchemeRegex = regexp.MustCompile(`((\w+|\*):(//)?)?(\*|\w+)(\.\w+)*(:(\d+|\*))?`)

// SourceContext is the context required by a CSP policy.
type SourceContext struct {
	URL          url.URL
	Page         url.URL
	UnsafeInline bool
	UnsafeEval   bool
	Nonce        string
	Body         []byte
}

// Report contains information about a CSP violation.
type Report struct {
	Document      string
	Blocked       string
	DirectiveName string
	Directive     Directive
	Context       SourceContext
}

func (s SourceContext) Report(name string, directive Directive, ctx SourceContext) Report {
	return Report{
		Document:      s.Page.String(),
		Blocked:       s.URL.String(),
		DirectiveName: name,
		Directive:     directive,
		Context:       ctx,
	}
}

// ParseSourceDirective parses a source directive arguments.
func ParseSourceDirective(sources []string) (SourceDirective, error) {
	s := SourceDirective{
		Nonces:  map[string]bool{},
		Schemes: map[string]bool{},
	}
	for _, sDef := range sources {
		if err := s.ParseSource(sDef); err != nil {
			return SourceDirective{}, err
		}
	}
	if err := s.Validate(); err != nil {
		return SourceDirective{}, err
	}
	return s, nil
}

// SourceDirective is used to enforce a CSP source policy on a URL.
type SourceDirective struct {
	ruleCount int

	None         bool
	Nonces       map[string]bool
	Hashes       []HashSource
	UnsafeEval   bool
	UnsafeInline bool
	Self         bool
	Schemes      map[string]bool
	Hosts        []glob.Glob
}

func urlSchemeHost(u url.URL) string {
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// Check that the SourceContext is allowed for this SourceDirective.
func (s SourceDirective) Check(ctx SourceContext) (bool, error) {
	if s.None {
		return false, nil
	}
	if ctx.UnsafeEval && !s.UnsafeEval {
		return false, nil
	}

	var originAllow bool
	isUnsafe := ctx.UnsafeInline
	if ctx.UnsafeInline && len(s.Nonces) == 0 && s.UnsafeInline {
		isUnsafe = false
		originAllow = true
	}

	if s.Self && ctx.URL.Host == ctx.Page.Host && ctx.URL.Scheme == ctx.Page.Scheme {
		originAllow = true
	}
	if s.Schemes[ctx.URL.Scheme] || s.Schemes["http"] && ctx.URL.Scheme == "https" {
		originAllow = true
	}
	if s.Nonces[ctx.Nonce] {
		originAllow = true
		isUnsafe = false
	}
	for _, hash := range s.Hashes {
		allow, err := hash.Check(ctx)
		if err != nil {
			return false, err
		}
		if allow {
			originAllow = true
			isUnsafe = false
		}
	}
	srcHost := urlSchemeHost(ctx.URL)
	for _, host := range s.Hosts {
		if host.Match(srcHost) {
			originAllow = true
		}
	}
	return originAllow && !isUnsafe, nil
}

// HashSource is a SourceDirective rule that matches the hash of content.
type HashSource struct {
	Algorithm func() hash.Hash
	Value     string
}

// Check if the ctx hash matches this hash.
func (s HashSource) Check(ctx SourceContext) (bool, error) {
	h := s.Algorithm()
	if _, err := h.Write(ctx.Body); err != nil {
		return false, err
	}
	hash := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return s.Value == hash, nil
}

// ParseSource parses a source and adds it to the SourceDirective.
func (s *SourceDirective) ParseSource(source string) error {
	s.ruleCount++

	if strings.HasPrefix(source, "'") && strings.HasSuffix(source, "'") {
		switch source {
		case "'self'":
			s.Self = true
			return nil
		case "'unsafe-inline'":
			s.UnsafeInline = true
			return nil
		case "'unsafe-eval'":
			s.UnsafeEval = true
			return nil
		case "'none'":
			s.None = true
			return nil
		case "'strict-dynamic'":
			// TODO: implement strict-dynamic
			return nil
		case "'report-sample'":
			// TODO: implement report-sample
			return nil
		}

		parts := strings.Split(source[1:len(source)-1], "-")
		if len(parts) == 2 {
			val := parts[1]

			var alg func() hash.Hash
			switch parts[0] {
			case "nonce":
				s.Nonces[val] = true
				return nil

			case "sha256":
				alg = sha256.New
			case "sha384":
				alg = sha512.New384
			case "sha512":
				alg = sha512.New
			}
			if alg != nil {
				s.Hashes = append(s.Hashes, HashSource{
					Algorithm: alg,
					Value:     val,
				})
				return nil
			}
		}
	} else {
		if strings.HasSuffix(source, ":") {
			s.Schemes[source[:len(source)-1]] = true
			return nil
		}
		if hostSchemeRegex.MatchString(source) {
			{
				g, err := glob.Compile(sanitizeGlob(source), '/')
				if err != nil {
					return err
				}
				s.Hosts = append(s.Hosts, g)
			}
			{
				g, err := glob.Compile("*://"+sanitizeGlob(source), '/')
				if err != nil {
					return err
				}
				s.Hosts = append(s.Hosts, g)
			}
			return nil
		}
	}
	return errors.Errorf("unknown source %q", source)
}

func sanitizeGlob(pattern string) string {
	parts := strings.Split(pattern, "*")
	for i, part := range parts {
		parts[i] = glob.QuoteMeta(part)
	}
	return strings.Join(parts, "*")
}

// Validate checks the source policy to make sure it's valid.
func (s *SourceDirective) Validate() error {
	if s.None && s.ruleCount != 1 {
		return errors.Errorf("'none' must only be specified")
	}
	return nil
}
