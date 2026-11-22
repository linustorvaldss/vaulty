package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Render writes entries in the requested output format, sorted by key.
func Render(entries []Entry, format Format) ([]byte, string, error) {
	sorted := append([]Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })

	switch format {
	case "", FormatDotenv:
		var b bytes.Buffer
		for _, e := range sorted {
			fmt.Fprintf(&b, "%s=%s\n", e.Key, quoteDotenv(e.Value))
		}
		return b.Bytes(), "text/plain; charset=utf-8", nil
	case FormatShell:
		var b bytes.Buffer
		for _, e := range sorted {
			fmt.Fprintf(&b, "export %s=%s\n", NormalizeKey(e.Key), quoteShell(e.Value))
		}
		return b.Bytes(), "text/plain; charset=utf-8", nil
	case FormatJSON:
		var b bytes.Buffer
		b.WriteString("{\n")
		for i, e := range sorted {
			k, _ := json.Marshal(e.Key)
			v, _ := json.Marshal(e.Value)
			fmt.Fprintf(&b, "  %s: %s", k, v)
			if i < len(sorted)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString("}\n")
		return b.Bytes(), "application/json", nil
	case FormatYAML:
		node := &yaml.Node{Kind: yaml.MappingNode}
		for _, e := range sorted {
			node.Content = append(node.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: e.Key},
				&yaml.Node{Kind: yaml.ScalarNode, Value: e.Value, Style: yaml.DoubleQuotedStyle})
		}
		out, err := yaml.Marshal(node)
		return out, "application/yaml", err
	default:
		return nil, "", fmt.Errorf("unsupported output format %q", format)
	}
}

var safeDotenv = regexp.MustCompile(`^[A-Za-z0-9_./:@+,=\-]*$`)

// quoteDotenv picks the safest quoting: bare for simple values, single quotes
// (literal, no expansion) when possible, double quotes with escapes otherwise.
func quoteDotenv(v string) string {
	if safeDotenv.MatchString(v) {
		return v
	}
	if !strings.ContainsAny(v, "'\n\r") {
		return "'" + v + "'"
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "$", `\$`, "`", "\\`")
	return `"` + r.Replace(v) + `"`
}

func quoteShell(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}
