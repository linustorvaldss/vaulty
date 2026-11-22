package parser

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func join(prefix, key, sep string) string {
	if prefix == "" {
		return key
	}
	return prefix + sep + key
}

// ---------- JSON / JSONC (settings.json, appsettings.json) ----------

func parseJSON(data []byte, sep string) (*Result, error) {
	clean := stripTrailingCommas(stripJSONComments(data))
	dec := json.NewDecoder(bytes.NewReader(clean))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("invalid JSON: top-level value must be an object")
	}
	res := &Result{}
	if err := walkJSONObject(dec, "", sep, res); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return res, nil
}

func walkJSONObject(dec *json.Decoder, prefix, sep string, res *Result) error {
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("expected object key, got %v", tok)
		}
		if err := walkJSONValue(dec, join(prefix, key, sep), sep, res); err != nil {
			return err
		}
	}
	_, err := dec.Token() // closing '}'
	return err
}

func walkJSONValue(dec *json.Decoder, path, sep string, res *Result) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			return walkJSONObject(dec, path, sep, res)
		case '[':
			for i := 0; dec.More(); i++ {
				if err := walkJSONValue(dec, join(path, strconv.Itoa(i), sep), sep, res); err != nil {
					return err
				}
			}
			_, err := dec.Token() // closing ']'
			return err
		}
	case string:
		res.Entries = append(res.Entries, Entry{Key: path, Value: v})
	case json.Number:
		res.Entries = append(res.Entries, Entry{Key: path, Value: v.String()})
	case bool:
		res.Entries = append(res.Entries, Entry{Key: path, Value: strconv.FormatBool(v)})
	case nil:
		res.Entries = append(res.Entries, Entry{Key: path, Value: ""})
	}
	return nil
}

// stripJSONComments removes // and /* */ comments outside of strings (JSONC).
func stripJSONComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inStr := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(data) {
				i++
				out = append(out, data[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(data) {
			switch data[i+1] {
			case '/':
				for i < len(data) && data[i] != '\n' {
					i++
				}
				if i < len(data) {
					out = append(out, '\n')
				}
				continue
			case '*':
				i += 2
				for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
					if data[i] == '\n' {
						out = append(out, '\n')
					}
					i++
				}
				i++ // skip '/'
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// stripTrailingCommas removes commas directly before } or ] (outside strings).
func stripTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inStr := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(data) {
				i++
				out = append(out, data[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
		}
		if c == ',' {
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// ---------- YAML ----------

func parseYAML(data []byte, sep string) (*Result, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	res := &Result{}
	if len(root.Content) == 0 {
		return res, nil
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil, errors.New("invalid YAML: top-level value must be a mapping")
	}
	walkYAML(doc, "", sep, res)
	return res, nil
}

func walkYAML(n *yaml.Node, path, sep string, res *Result) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			walkYAML(n.Content[i+1], join(path, n.Content[i].Value, sep), sep, res)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			walkYAML(c, join(path, strconv.Itoa(i), sep), sep, res)
		}
	case yaml.AliasNode:
		walkYAML(n.Alias, path, sep, res)
	case yaml.ScalarNode:
		v := n.Value
		if n.Tag == "!!null" {
			v = ""
		}
		res.Entries = append(res.Entries, Entry{Key: path, Value: v, Line: n.Line})
	}
}

// ---------- XML ----------

type xmlNode struct {
	name     string
	attrs    []xml.Attr
	text     strings.Builder
	children []*xmlNode
}

// parseXML flattens XML documents. It understands the .NET conventions
// <add key="K" value="V"/> (appSettings) and <add name="K" connectionString="V"/>
// (connectionStrings); any other element becomes a path of element names
// (root excluded), attributes become path<sep>attr, repeated siblings get an index.
func parseXML(data []byte, sep string) (*Result, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	var (
		stack []*xmlNode
		root  *xmlNode
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &xmlNode{name: t.Name.Local, attrs: t.Attr}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			} else if root == nil {
				root = n
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(t)
			}
		}
	}
	if root == nil {
		return nil, errors.New("invalid XML: no root element")
	}
	res := &Result{}
	walkXMLChildren(root, "", sep, res)
	return res, nil
}

func attr(n *xmlNode, name string) (string, bool) {
	for _, a := range n.attrs {
		if strings.EqualFold(a.Name.Local, name) {
			return a.Value, true
		}
	}
	return "", false
}

func walkXMLChildren(n *xmlNode, path, sep string, res *Result) {
	counts := map[string]int{}
	for _, c := range n.children {
		counts[c.name]++
	}
	seen := map[string]int{}
	for _, c := range n.children {
		if strings.EqualFold(c.name, "add") {
			if k, ok := attr(c, "key"); ok {
				v, _ := attr(c, "value")
				res.Entries = append(res.Entries, Entry{Key: k, Value: v})
				continue
			}
			if k, ok := attr(c, "name"); ok {
				if v, ok := attr(c, "connectionString"); ok {
					res.Entries = append(res.Entries, Entry{Key: k, Value: v})
					continue
				}
			}
		}
		name := c.name
		if counts[c.name] > 1 {
			name = name + sep + strconv.Itoa(seen[c.name])
			seen[c.name]++
		}
		walkXMLNode(c, join(path, name, sep), sep, res)
	}
}

func walkXMLNode(n *xmlNode, path, sep string, res *Result) {
	for _, a := range n.attrs {
		if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
			continue
		}
		res.Entries = append(res.Entries, Entry{Key: join(path, a.Name.Local, sep), Value: a.Value})
	}
	if len(n.children) == 0 {
		text := strings.TrimSpace(n.text.String())
		if text != "" || len(n.attrs) == 0 {
			res.Entries = append(res.Entries, Entry{Key: path, Value: text})
		}
		return
	}
	walkXMLChildren(n, path, sep, res)
}
