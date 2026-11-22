// Package parser turns configuration files (.env, JSON, settings.json /
// appsettings.json, XML, YAML) into flat key/value entries, and renders
// entries back into those formats. It is pure: no I/O, no domain deps.
package parser

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type Format string

const (
	FormatAuto   Format = "auto"
	FormatDotenv Format = "dotenv"
	FormatJSON   Format = "json" // also JSONC: settings.json, appsettings.json, tsconfig-like files
	FormatXML    Format = "xml"
	FormatYAML   Format = "yaml"
	FormatShell  Format = "shell" // output only: `export KEY='value'`
)

// Entry is one parsed secret.
type Entry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Line  int    `json:"line,omitempty"`
}

// Issue is a non-fatal problem found while parsing a specific line/key.
type Issue struct {
	Line    int    `json:"line,omitempty"`
	Key     string `json:"key,omitempty"`
	Message string `json:"message"`
}

type Options struct {
	// Separator joins nested keys when flattening structured formats.
	// Default "__" (the .NET / 12-factor convention: Logging__LogLevel__Default).
	Separator string
	// Normalize upper-cases keys and replaces invalid env-var characters with "_".
	Normalize bool
	// Prefix is prepended to every key.
	Prefix string
}

type Result struct {
	Format  Format  `json:"format"`
	Entries []Entry `json:"entries"`
	Issues  []Issue `json:"issues,omitempty"`
}

// Parse detects (when format is auto/empty) and parses data.
func Parse(data []byte, format Format, filename string, opts Options) (*Result, error) {
	if opts.Separator == "" {
		opts.Separator = "__"
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // UTF-8 BOM
	if format == "" || format == FormatAuto {
		format = Detect(filename, data)
	}

	var (
		res *Result
		err error
	)
	switch format {
	case FormatDotenv:
		res = parseDotenv(data)
	case FormatJSON:
		res, err = parseJSON(data, opts.Separator)
	case FormatXML:
		res, err = parseXML(data, opts.Separator)
	case FormatYAML:
		res, err = parseYAML(data, opts.Separator)
	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return nil, err
	}
	res.Format = format
	finalize(res, opts)
	return res, nil
}

// Detect guesses the format from the file name, then from the content.
func Detect(filename string, data []byte) Format {
	name := strings.ToLower(filepath.Base(filename))
	switch {
	case name == ".env" || strings.HasPrefix(name, ".env.") || strings.HasSuffix(name, ".env"):
		return FormatDotenv
	case strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".jsonc"):
		return FormatJSON
	case strings.HasSuffix(name, ".xml") || strings.HasSuffix(name, ".config"):
		return FormatXML
	case strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml"):
		return FormatYAML
	}
	trimmed := bytes.TrimSpace(stripJSONComments(data))
	switch {
	case bytes.HasPrefix(trimmed, []byte("{")):
		return FormatJSON
	case bytes.HasPrefix(trimmed, []byte("<")):
		return FormatXML
	}
	if looksLikeYAML(data) {
		return FormatYAML
	}
	return FormatDotenv
}

var yamlLine = regexp.MustCompile(`^\s*[A-Za-z0-9_.\-"']+\s*:(\s|$)`)
var envLine = regexp.MustCompile(`^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_.\-]*\s*=`)

func looksLikeYAML(data []byte) bool {
	yamlHits, envHits := 0, 0
	for _, l := range strings.Split(string(data), "\n") {
		switch {
		case envLine.MatchString(l):
			envHits++
		case yamlLine.MatchString(l):
			yamlHits++
		}
	}
	return yamlHits > envHits
}

var invalidEnvChars = regexp.MustCompile(`[^A-Za-z0-9_]`)

// NormalizeKey converts "database.url" / "my-key" into "DATABASE_URL" / "MY_KEY".
func NormalizeKey(k string) string {
	k = invalidEnvChars.ReplaceAllString(k, "_")
	if k != "" && k[0] >= '0' && k[0] <= '9' {
		k = "_" + k
	}
	return strings.ToUpper(k)
}

// finalize applies prefix/normalization and de-duplicates keys (last wins,
// first position kept).
func finalize(res *Result, opts Options) {
	index := make(map[string]int, len(res.Entries))
	out := make([]Entry, 0, len(res.Entries))
	for _, e := range res.Entries {
		e.Key = opts.Prefix + e.Key
		if opts.Normalize {
			e.Key = NormalizeKey(e.Key)
		}
		if i, ok := index[e.Key]; ok {
			res.Issues = append(res.Issues, Issue{Line: e.Line, Key: e.Key, Message: "duplicate key, last value wins"})
			out[i].Value = e.Value
			continue
		}
		index[e.Key] = len(out)
		out = append(out, e)
	}
	res.Entries = out
}
