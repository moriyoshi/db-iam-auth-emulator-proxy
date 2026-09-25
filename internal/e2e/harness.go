// Package e2e runs isolated Starlark scenarios against real database containers
// and the production proxy binary. Scenarios can spawn explicit CLI commands.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

var fileOptions = &syntax.FileOptions{TopLevelControl: true, GlobalReassign: true}

type Options struct {
	Proxy          string
	FixtureImage   string
	FixtureTimeout time.Duration
}

func (o Options) defaults() Options {
	if o.Proxy == "" {
		o.Proxy = "db-iam-auth-emulator-proxy"
	}
	if o.FixtureImage == "" {
		o.FixtureImage = "db-iam-auth-emulator-proxy-e2e:local"
	}
	if o.FixtureTimeout <= 0 {
		o.FixtureTimeout = 90 * time.Second
	}
	return o
}

type Harness struct {
	options       Options
	out           io.Writer
	ctx           context.Context
	environment   []string
	root          string
	containers    []string
	databases     map[string]string
	proxy         *os.Process
	proxyDone     chan error
	proxyLog      *lockedBuffer
	listeners     map[string]listenerInfo
	httpAddr      string
	httpsAddr     string
	certPath      string
	googleADCPath string
	awsConfigPath string
}
type listenerInfo struct {
	Addr     string
	Provider string
	Engine   string
}

func New(options Options, out io.Writer) *Harness {
	if out == nil {
		out = io.Discard
	}
	return &Harness{options: options.defaults(), out: out, environment: os.Environ(), databases: map[string]string{}, listeners: map[string]listenerInfo{}}
}

func names() map[string]bool {
	result := map[string]bool{}
	for _, n := range []string{"postgres", "mysql", "mariadb", "start_proxy", "set_env", "spawn", "query", "assert_eq", "assert_true", "proxy_log", "log"} {
		result[n] = true
	}
	return result
}

func Check(path string) error {
	return checkFile(path, map[string]bool{})
}

func scenarioModule(path, name string) (string, error) {
	if filepath.Base(name) != name || name == ".." || !strings.HasSuffix(name, ".star") {
		return "", fmt.Errorf("invalid scenario module %q", name)
	}
	return filepath.Join(filepath.Dir(path), name), nil
}

func checkFile(path string, seen map[string]bool) error {
	if seen[path] {
		return nil
	}
	seen[path] = true
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, program, err := starlark.SourceProgramOptions(fileOptions, path, src, func(n string) bool { return names()[n] })
	if err != nil {
		return err
	}
	for i := 0; i < program.NumLoads(); i++ {
		name, _ := program.Load(i)
		module, err := scenarioModule(path, name)
		if err != nil {
			return err
		}
		if err := checkFile(module, seen); err != nil {
			return err
		}
	}
	return nil
}

func (h *Harness) builtins() starlark.StringDict {
	return starlark.StringDict{
		"postgres": starlark.NewBuiltin("postgres", h.bPostgres), "mysql": starlark.NewBuiltin("mysql", h.bMySQL), "mariadb": starlark.NewBuiltin("mariadb", h.bMariaDB),
		"start_proxy": starlark.NewBuiltin("start_proxy", h.bStartProxy), "set_env": starlark.NewBuiltin("set_env", h.bSetEnv), "spawn": starlark.NewBuiltin("spawn", h.bSpawn),
		"query": starlark.NewBuiltin("query", h.bQuery), "assert_eq": starlark.NewBuiltin("assert_eq", h.bAssertEq),
		"assert_true": starlark.NewBuiltin("assert_true", h.bAssertTrue), "proxy_log": starlark.NewBuiltin("proxy_log", h.bProxyLog), "log": starlark.NewBuiltin("log", h.bLog),
	}
}

func (h *Harness) RunFile(ctx context.Context, path string) (result error) {
	if ctx == nil {
		return errors.New("nil context")
	}
	h.ctx = ctx
	root, err := os.MkdirTemp("", "iam-proxy-e2e-")
	if err != nil {
		return err
	}
	h.root = root
	defer func() { result = errors.Join(result, h.close()) }()
	thread := &starlark.Thread{Name: path, Print: func(_ *starlark.Thread, msg string) { fmt.Fprintln(h.out, msg) }}
	modules := map[string]starlark.StringDict{}
	loading := map[string]bool{}
	thread.Load = func(thread *starlark.Thread, name string) (starlark.StringDict, error) {
		module, err := scenarioModule(path, name)
		if err != nil {
			return nil, err
		}
		if value, ok := modules[module]; ok {
			return value, nil
		}
		if loading[module] {
			return nil, fmt.Errorf("scenario module cycle: %s", name)
		}
		loading[module] = true
		defer delete(loading, module)
		value, err := starlark.ExecFileOptions(fileOptions, thread, module, nil, h.builtins())
		if err != nil {
			return nil, err
		}
		modules[module] = value
		return value, nil
	}
	_, err = starlark.ExecFileOptions(fileOptions, thread, path, nil, h.builtins())
	if err != nil {
		return fmt.Errorf("scenario %s: %w", path, err)
	}
	return nil
}

func (h *Harness) bPostgres(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("postgres", args, kwargs); err != nil {
		return nil, err
	}
	if err := h.startDatabase("postgres"); err != nil {
		return nil, err
	}
	return starlark.None, nil
}
func (h *Harness) bMySQL(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("mysql", args, kwargs); err != nil {
		return nil, err
	}
	if err := h.startDatabase("mysql"); err != nil {
		return nil, err
	}
	return starlark.None, nil
}
func (h *Harness) bMariaDB(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("mariadb", args, kwargs); err != nil {
		return nil, err
	}
	if err := h.startDatabase("mariadb"); err != nil {
		return nil, err
	}
	return starlark.None, nil
}
func (h *Harness) bStartProxy(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("start_proxy", args, kwargs); err != nil {
		return nil, err
	}
	if err := h.startProxy(); err != nil {
		return nil, err
	}
	return h.proxyDetails()
}
func (h *Harness) bQuery(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var provider, engine, token, sql string
	if err := starlark.UnpackArgs("query", args, kwargs, "provider", &provider, "engine", &engine, "token", &token, "sql?", &sql); err != nil {
		return nil, err
	}
	if sql == "" {
		sql = "select 1"
	}
	result, err := h.query(provider, engine, token, sql)
	if err != nil {
		return nil, err
	}
	return starlark.String(result), nil
}
func (h *Harness) bAssertEq(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var got, want starlark.Value
	if err := starlark.UnpackArgs("assert_eq", args, kwargs, "got", &got, "want", &want); err != nil {
		return nil, err
	}
	equal, err := starlark.Equal(got, want)
	if err != nil {
		return nil, err
	}
	if !equal {
		return nil, fmt.Errorf("got %s, want %s", got, want)
	}
	return starlark.None, nil
}
func (h *Harness) bAssertTrue(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("assert_true", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	if !bool(value.Truth()) {
		return nil, errors.New("assert_true failed")
	}
	return starlark.None, nil
}
func (h *Harness) bProxyLog(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("proxy_log", args, kwargs); err != nil {
		return nil, err
	}
	if h.proxyLog == nil {
		return starlark.String(""), nil
	}
	return starlark.String(h.proxyLog.String()), nil
}
func (h *Harness) bLog(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var msg string
	if err := starlark.UnpackArgs("log", args, kwargs, "message", &msg); err != nil {
		return nil, err
	}
	fmt.Fprintln(h.out, "•", msg)
	return starlark.None, nil
}

func (h *Harness) close() error {
	var errs []error
	if h.proxy != nil {
		_ = h.proxy.Signal(os.Interrupt)
		select {
		case <-h.proxyDone:
		case <-time.After(5 * time.Second):
			_ = h.proxy.Kill()
			<-h.proxyDone
		}
		h.proxy = nil
	}
	for i := len(h.containers) - 1; i >= 0; i-- {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := capture(ctx, "docker", "rm", "-f", h.containers[i])
		cancel()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if h.root != "" {
		if err := os.RemoveAll(h.root); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func Preflight(ctx context.Context) error {
	out, err := capture(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
	if err != nil {
		return fmt.Errorf("Docker unavailable: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}
