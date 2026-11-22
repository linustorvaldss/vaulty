// Command vaulty is the Vaulty CLI: log in with an access token, pull
// secrets into files or straight into a process environment, push files.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/linustorvaldss/vaulty/internal/client"
)

const usage = `vaulty - secrets for your environments

Usage:
  vaulty login [--token vty_...] [--api URL]   save an access token (created in the web app)
  vaulty logout                                 remove saved credentials
  vaulty whoami                                 show the authenticated user
  vaulty projects                               list projects
  vaulty link -p PROJECT [-e ENV]               bind this directory (writes .vaulty.json)

  vaulty pull  [-p P] [-e E] [-f dotenv|json|yaml|shell] [-o FILE]
  vaulty run   [-p P] [-e E] -- COMMAND [ARGS...]   run with secrets as env vars
  vaulty push  FILE [-p P] [-e E] [--strategy overwrite|skip|fail] [--dry-run]
               [--format auto|dotenv|json|xml|yaml] [--normalize] [--separator __] [--prefix X]

  vaulty list  [-p P] [-e E] [--reveal]
  vaulty get   KEY [-p P] [-e E]
  vaulty set   KEY=VALUE [KEY=VALUE...] [-p P] [-e E]
  vaulty unset KEY [KEY...] [-p P] [-e E]
  vaulty share [-p P] [-e E] [--keys A,B] [--hours 24] [--max-views N] [--passphrase X]

Environment: VAULTY_TOKEN, VAULTY_API_URL, VAULTY_PROJECT, VAULTY_ENV
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	cmds := map[string]func([]string) error{
		"login": cmdLogin, "logout": cmdLogout, "whoami": cmdWhoami, "projects": cmdProjects, "link": cmdLink,
		"pull": cmdPull, "run": cmdRun, "push": cmdPush,
		"list": cmdList, "get": cmdGet, "set": cmdSet, "unset": cmdUnset, "share": cmdShare,
	}
	fn, ok := cmds[cmd]
	if !ok {
		if cmd != "help" && cmd != "-h" && cmd != "--help" {
			fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		}
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := fn(args); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// ---------- credentials & project link ----------

type credentials struct {
	APIURL string `json:"api_url"`
	Token  string `json:"token"`
}

func credentialsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vaulty", "credentials.json"), nil
}

func loadCredentials() credentials {
	var c credentials
	if p, err := credentialsPath(); err == nil {
		if b, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(b, &c)
		}
	}
	if v := os.Getenv("VAULTY_API_URL"); v != "" {
		c.APIURL = v
	}
	if v := os.Getenv("VAULTY_TOKEN"); v != "" {
		c.Token = v
	}
	if c.APIURL == "" {
		c.APIURL = "http://localhost:8080"
	}
	return c
}

func newClient() (*client.Client, error) {
	c := loadCredentials()
	if c.Token == "" {
		return nil, errors.New("not logged in: run `vaulty login` or set VAULTY_TOKEN")
	}
	return client.New(c.APIURL, c.Token), nil
}

const linkFile = ".vaulty.json"

type link struct {
	Project     string `json:"project"`
	Environment string `json:"environment,omitempty"`
}

// findLink searches .vaulty.json from the cwd upwards.
func findLink() link {
	dir, _ := os.Getwd()
	for dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, linkFile)); err == nil {
			var l link
			_ = json.Unmarshal(b, &l)
			return l
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return link{}
}

// target adds -p/-e flags and resolves them: flag > env var > .vaulty.json.
type target struct{ project, env *string }

func addTarget(fs *flag.FlagSet) target {
	return target{
		project: fs.String("p", "", "project slug or id"),
		env:     fs.String("e", "", "environment slug (default development)"),
	}
}

func (t target) resolve() (string, string, error) {
	l := findLink()
	project := first(*t.project, os.Getenv("VAULTY_PROJECT"), l.Project)
	env := first(*t.env, os.Getenv("VAULTY_ENV"), l.Environment, "development")
	if project == "" {
		return "", "", errors.New("no project: use -p, VAULTY_PROJECT or `vaulty link`")
	}
	return project, env, nil
}

func first(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// parse lets flags appear before or after positional args.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Minute)
}

// ---------- commands ----------

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	token := fs.String("token", "", "access token (vty_...)")
	api := fs.String("api", "", "API URL")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c := loadCredentials()
	if *api != "" {
		c.APIURL = *api
	}
	c.Token = *token
	if c.Token == "" {
		fmt.Fprint(os.Stderr, "Paste your access token (create one in Settings > Access tokens): ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		c.Token = strings.TrimSpace(line)
	}
	if !strings.HasPrefix(c.Token, "vty_") {
		return errors.New("invalid token: expected a vty_ access token")
	}
	cx, cancel := ctx()
	defer cancel()
	me, err := client.New(c.APIURL, c.Token).Me(cx)
	if err != nil {
		return fmt.Errorf("token rejected: %w", err)
	}
	p, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	fmt.Printf("Logged in as %s (%s)\n", me.User.Email, c.APIURL)
	return nil
}

func cmdLogout([]string) error {
	p, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Println("Logged out")
	return nil
}

func cmdWhoami([]string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	me, err := c.Me(cx)
	if err != nil {
		return err
	}
	fmt.Printf("%s <%s>\n", me.User.Name, me.User.Email)
	for _, t := range me.Tenants {
		if me.TokenTenantID == "" || t.ID == me.TokenTenantID {
			mode := ""
			if me.ReadOnly {
				mode = ", read-only token"
			}
			fmt.Printf("workspace: %s (%s, %s%s)\n", t.Name, t.Slug, t.Role, mode)
		}
	}
	return nil
}

func cmdProjects([]string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	ps, err := c.Projects(cx)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SLUG\tNAME")
	for _, p := range ps {
		fmt.Fprintf(w, "%s\t%s\n", p.Slug, p.Name)
	}
	return w.Flush()
}

func cmdLink(args []string) error {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	t := addTarget(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	project, env, err := t.resolve()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	p, err := c.Project(cx, project)
	if err != nil {
		return err
	}
	found := false
	for _, e := range p.Environments {
		found = found || e.Slug == env
	}
	if !found {
		return fmt.Errorf("environment %q does not exist in %s", env, p.Slug)
	}
	b, _ := json.MarshalIndent(link{Project: p.Slug, Environment: env}, "", "  ")
	if err := os.WriteFile(linkFile, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("Linked to %s/%s (%s)\n", p.Slug, env, linkFile)
	return nil
}

func cmdPull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	t := addTarget(fs)
	format := fs.String("f", "dotenv", "dotenv|json|yaml|shell")
	out := fs.String("o", "", "write to file (0600) instead of stdout")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	project, env, err := t.resolve()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	data, err := c.Export(cx, project, env, *format)
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Wrote %s/%s to %s\n", project, env, *out)
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	t := addTarget(fs)
	// Flags only before the command: everything after it belongs to the child.
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return errors.New("usage: vaulty run [-p P] [-e E] -- COMMAND [ARGS...]")
	}
	project, env, err := t.resolve()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	secrets, err := c.ExportMap(cx, project, env)
	cancel()
	if err != nil {
		return err
	}
	environ := os.Environ()
	for k, v := range secrets {
		environ = append(environ, k+"="+v) // later entries win
	}
	cmd := exec.Command(rest[0], rest[1:]...)
	cmd.Env = environ
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Let the child handle Ctrl+C itself.
	signal.Ignore(os.Interrupt)
	return cmd.Run()
}

func cmdPush(args []string) error {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	t := addTarget(fs)
	var o client.ImportOptions
	fs.StringVar(&o.Strategy, "strategy", "overwrite", "overwrite|skip|fail")
	fs.StringVar(&o.Format, "format", "auto", "auto|dotenv|json|xml|yaml")
	fs.BoolVar(&o.DryRun, "dry-run", false, "show what would change")
	fs.BoolVar(&o.Normalize, "normalize", false, "upper-case keys, replace invalid chars with _")
	fs.StringVar(&o.Separator, "separator", "", "nested key separator (default __)")
	fs.StringVar(&o.Prefix, "prefix", "", "prefix added to every key")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: vaulty push FILE [flags]")
	}
	data, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}
	project, env, err := t.resolve()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	res, err := c.Import(cx, project, env, rest[0], data, o)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tACTION\tDETAIL")
	for _, it := range res.Items {
		fmt.Fprintf(w, "%s\t%s\t%s\n", it.Key, it.Action, it.Error)
	}
	w.Flush()
	for _, is := range res.Issues {
		fmt.Fprintf(os.Stderr, "warning: line %d: %s\n", is.Line, is.Message)
	}
	keys := make([]string, 0, len(res.Summary))
	for k := range res.Summary {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%d %s", res.Summary[k], k)
	}
	prefix := ""
	if res.DryRun {
		prefix = "(dry run) "
	}
	fmt.Printf("%s%s → %s/%s [%s]: %s\n", prefix, rest[0], project, env, res.Format, strings.Join(parts, ", "))
	if res.Summary["error"] > 0 {
		return fmt.Errorf("%d keys failed", res.Summary["error"])
	}
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	t := addTarget(fs)
	reveal := fs.Bool("reveal", false, "show values")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	project, env, err := t.resolve()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	secrets, err := c.ListSecrets(cx, project, env, *reveal)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tVERSION\tUPDATED\tVALUE")
	for _, s := range secrets {
		v := "••••••"
		if s.Value != nil {
			v = *s.Value
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", s.Key, s.Version, s.UpdatedAt.Local().Format("2006-01-02 15:04"), v)
	}
	return w.Flush()
}

func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	t := addTarget(fs)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: vaulty get KEY")
	}
	project, env, err := t.resolve()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	s, err := c.GetSecret(cx, project, env, rest[0])
	if err != nil {
		return err
	}
	if s.Value != nil {
		fmt.Println(*s.Value)
	}
	return nil
}

func cmdSet(args []string) error {
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	t := addTarget(fs)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return errors.New("usage: vaulty set KEY=VALUE [KEY=VALUE...]")
	}
	project, env, err := t.resolve()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	for _, kv := range rest {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("expected KEY=VALUE, got %q", kv)
		}
		if err := c.SetSecret(cx, project, env, k, v); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		fmt.Printf("set %s in %s/%s\n", k, project, env)
	}
	return nil
}

func cmdUnset(args []string) error {
	fs := flag.NewFlagSet("unset", flag.ExitOnError)
	t := addTarget(fs)
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return errors.New("usage: vaulty unset KEY [KEY...]")
	}
	project, env, err := t.resolve()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	for _, k := range rest {
		if err := c.DeleteSecret(cx, project, env, k); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		fmt.Printf("deleted %s from %s/%s\n", k, project, env)
	}
	return nil
}

func cmdShare(args []string) error {
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	t := addTarget(fs)
	keys := fs.String("keys", "", "comma-separated keys (default: all)")
	hours := fs.Int("hours", 24, "expiration in hours (max 720)")
	views := fs.Int("max-views", 0, "maximum number of views (0 = unlimited)")
	pass := fs.String("passphrase", "", "require a passphrase to open")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	project, env, err := t.resolve()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	in := map[string]any{"expires_in_hours": *hours, "max_views": *views, "passphrase": *pass}
	if *keys != "" {
		in["keys"] = strings.Split(*keys, ",")
	}
	cx, cancel := ctx()
	defer cancel()
	r, err := c.Share(cx, project, env, in)
	if err != nil {
		return err
	}
	fmt.Println(r.URL)
	views2 := "unlimited views"
	if r.MaxViews > 0 {
		views2 = strconv.Itoa(r.MaxViews) + " views"
	}
	fmt.Fprintf(os.Stderr, "expires %s, %s\nraw: curl -s '%s?format=dotenv'\n", r.ExpiresAt.Local().Format(time.RFC1123), views2, r.APIURL)
	return nil
}
