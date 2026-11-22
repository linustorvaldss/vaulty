package parser

import (
	"strings"
	"testing"
)

func toMap(r *Result) map[string]string {
	m := map[string]string{}
	for _, e := range r.Entries {
		m[e.Key] = e.Value
	}
	return m
}

func expect(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d entries %v, want %d", len(got), got, len(want))
	}
}

func TestDotenv(t *testing.T) {
	src := "# comment\n" +
		"export A=1\n" +
		"B = hello world # trailing\n" +
		"C=\"line1\\nline2 \\\"q\\\"\"\n" +
		"D='literal $HOME \\n'\n" +
		"E=\"multi\n" +
		"line\"\n" +
		"F=\n" +
		"bad line\n" +
		"URL=postgres://u:p@h:5432/db?sslmode=disable#frag\n"
	r, err := Parse([]byte(src), FormatAuto, ".env", Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, toMap(r), map[string]string{
		"A": "1", "B": "hello world", "C": "line1\nline2 \"q\"", "D": `literal $HOME \n`,
		"E": "multi\nline", "F": "", "URL": "postgres://u:p@h:5432/db?sslmode=disable#frag",
	})
	if len(r.Issues) != 1 || r.Issues[0].Line != 9 {
		t.Errorf("issues = %+v", r.Issues)
	}
}

func TestJSONCSettings(t *testing.T) {
	src := `{
  // VS Code style comment
  "Logging": { "LogLevel": { "Default": "Information" } },
  "ConnectionStrings": { "Db": "Server=x;Password=a//b" }, /* block */
  "Hosts": ["a", "b"],
  "Port": 8080,
  "Debug": true,
  "Empty": null,
}`
	r, err := Parse([]byte(src), FormatAuto, "appsettings.json", Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, toMap(r), map[string]string{
		"Logging__LogLevel__Default": "Information",
		"ConnectionStrings__Db":      "Server=x;Password=a//b",
		"Hosts__0":                   "a", "Hosts__1": "b",
		"Port": "8080", "Debug": "true", "Empty": "",
	})
	if r.Entries[0].Key != "Logging__LogLevel__Default" {
		t.Errorf("order not preserved: %v", r.Entries[0].Key)
	}
}

func TestJSONNormalize(t *testing.T) {
	r, err := Parse([]byte(`{"editor.fontSize": 14, "db": {"url": "x"}}`), FormatJSON, "", Options{Normalize: true, Separator: "_"})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, toMap(r), map[string]string{"EDITOR_FONTSIZE": "14", "DB_URL": "x"})
}

func TestXML(t *testing.T) {
	src := `<?xml version="1.0"?>
<configuration>
  <appSettings>
    <add key="ApiKey" value="abc"/>
  </appSettings>
  <connectionStrings>
    <add name="Main" connectionString="Server=.;Db=x" providerName="sql"/>
  </connectionStrings>
  <smtp host="mail" port="25"><user>bob</user></smtp>
  <server>a</server><server>b</server>
</configuration>`
	r, err := Parse([]byte(src), FormatAuto, "web.config", Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, toMap(r), map[string]string{
		"ApiKey": "abc", "Main": "Server=.;Db=x",
		"smtp__host": "mail", "smtp__port": "25", "smtp__user": "bob",
		"server__0": "a", "server__1": "b",
	})
}

func TestYAMLAndDetect(t *testing.T) {
	src := "db:\n  host: localhost\n  port: 5432\nlist:\n  - x\n"
	if f := Detect("", []byte(src)); f != FormatYAML {
		t.Fatalf("detect = %s", f)
	}
	r, err := Parse([]byte(src), FormatAuto, "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, toMap(r), map[string]string{"db__host": "localhost", "db__port": "5432", "list__0": "x"})
	if f := Detect("", []byte("A=1\nB: weird\nC=3")); f != FormatDotenv {
		t.Fatalf("detect = %s", f)
	}
}

func TestRenderRoundTrip(t *testing.T) {
	entries := []Entry{
		{Key: "SIMPLE", Value: "abc"},
		{Key: "SPACES", Value: "hello world"},
		{Key: "MULTI", Value: "a\nb'c $X"},
		{Key: "QUOTE", Value: `it's "x"`},
	}
	out, _, err := Render(entries, FormatDotenv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Parse(out, FormatDotenv, "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, toMap(r), map[string]string{"SIMPLE": "abc", "SPACES": "hello world", "MULTI": "a\nb'c $X", "QUOTE": `it's "x"`})

	for _, f := range []Format{FormatJSON, FormatYAML} {
		out, _, err := Render(entries, f)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Parse(out, f, "", Options{})
		if err != nil {
			t.Fatalf("%s: %v\n%s", f, err, out)
		}
		expect(t, toMap(r), map[string]string{"SIMPLE": "abc", "SPACES": "hello world", "MULTI": "a\nb'c $X", "QUOTE": `it's "x"`})
	}

	sh, _, _ := Render([]Entry{{Key: "a.b", Value: "it's"}}, FormatShell)
	if strings.TrimSpace(string(sh)) != `export A_B='it'\''s'` {
		t.Errorf("shell = %s", sh)
	}
}
