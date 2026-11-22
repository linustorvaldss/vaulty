package parser

import (
	"strings"
)

// parseDotenv parses KEY=VALUE files. Supports `export` prefixes, comments,
// single/double/backtick quotes, multiline quoted values and escapes inside
// double quotes. Variables ($VAR) are kept literally (no expansion).
func parseDotenv(data []byte) *Result {
	res := &Result{}
	src := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(src, "\n")

	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimLeft(line, " \t")

		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			res.Issues = append(res.Issues, Issue{Line: lineNo, Message: "expected KEY=VALUE"})
			continue
		}
		key := strings.TrimSpace(line[:eq])
		rest := strings.TrimLeft(line[eq+1:], " \t")

		if rest == "" {
			res.Entries = append(res.Entries, Entry{Key: key, Value: "", Line: lineNo})
			continue
		}

		switch q := rest[0]; q {
		case '"', '\'', '`':
			// Collect until the closing quote, possibly across lines.
			body := rest[1:]
			startLine := lineNo
			for {
				if end := closingQuote(body, q); end >= 0 {
					val := body[:end]
					if q == '"' {
						val = unescapeDouble(val)
					}
					res.Entries = append(res.Entries, Entry{Key: key, Value: val, Line: startLine})
					break
				}
				i++
				if i >= len(lines) {
					res.Issues = append(res.Issues, Issue{Line: startLine, Key: key, Message: "unterminated quoted value"})
					break
				}
				body += "\n" + lines[i]
			}
		default:
			val := rest
			if idx := strings.Index(val, " #"); idx >= 0 {
				val = val[:idx]
			} else if idx := strings.Index(val, "\t#"); idx >= 0 {
				val = val[:idx]
			}
			res.Entries = append(res.Entries, Entry{Key: key, Value: strings.TrimSpace(val), Line: lineNo})
		}
	}
	return res
}

// closingQuote returns the index of the closing quote in s, honouring
// backslash escapes for double quotes.
func closingQuote(s string, q byte) int {
	for i := 0; i < len(s); i++ {
		if q == '"' && s[i] == '\\' {
			i++
			continue
		}
		if s[i] == q {
			return i
		}
	}
	return -1
}

func unescapeDouble(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '"', '\\', '$', '`':
			b.WriteByte(s[i])
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
