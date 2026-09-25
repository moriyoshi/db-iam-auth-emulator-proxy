package e2e

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"go.starlark.net/starlark"
)

// bSetEnv updates the environment inherited by later spawn calls in this scenario.
func (h *Harness) bSetEnv(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values *starlark.Dict
	var unsetPrefixes *starlark.List
	if err := starlark.UnpackArgs("set_env", args, kwargs, "values", &values, "unset_prefixes?", &unsetPrefixes); err != nil {
		return nil, err
	}
	if values == nil {
		return nil, fmt.Errorf("set_env requires a dictionary")
	}
	overrides := map[string]string{}
	for _, key := range values.Keys() {
		name, ok := starlark.AsString(key)
		if !ok || name == "" || strings.ContainsAny(name, "=\x00") {
			return nil, fmt.Errorf("set_env contains an invalid name")
		}
		value, _, err := values.Get(key)
		if err != nil {
			return nil, err
		}
		text, ok := starlark.AsString(value)
		if !ok || strings.ContainsRune(text, '\x00') {
			return nil, fmt.Errorf("set_env[%q] must be a string without NUL", name)
		}
		overrides[name] = text
	}
	var prefixes []string
	if unsetPrefixes != nil {
		for i := 0; i < unsetPrefixes.Len(); i++ {
			prefix, ok := starlark.AsString(unsetPrefixes.Index(i))
			if !ok || prefix == "" {
				return nil, fmt.Errorf("set_env unset_prefixes[%d] must be a nonempty string", i)
			}
			prefixes = append(prefixes, prefix)
		}
	}
	var environment []string
	for _, item := range h.environment {
		name, _, _ := strings.Cut(item, "=")
		if _, replaced := overrides[name]; replaced {
			continue
		}
		remove := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(name, prefix) {
				remove = true
				break
			}
		}
		if !remove {
			environment = append(environment, item)
		}
	}
	for key, value := range overrides {
		environment = append(environment, key+"="+value)
	}
	h.environment = environment
	return starlark.None, nil
}

// bSpawn runs a command selected by the checked-in scenario, inheriting its
// environment. Only stdout becomes the Starlark value, so warnings cannot
// corrupt a credential returned by a CLI.
func (h *Harness) bSpawn(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var argv *starlark.List
	if err := starlark.UnpackArgs("spawn", args, kwargs, "argv", &argv); err != nil {
		return nil, err
	}
	if argv == nil || argv.Len() == 0 {
		return nil, fmt.Errorf("spawn requires a nonempty argv")
	}
	command := make([]string, argv.Len())
	for i := range command {
		value, ok := starlark.AsString(argv.Index(i))
		if !ok {
			return nil, fmt.Errorf("spawn argv[%d] must be a string", i)
		}
		command[i] = value
	}
	cmd := exec.CommandContext(h.ctx, command[0], command[1:]...)
	cmd.Dir = h.root
	cmd.Env = h.environment
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("spawn %s: %w: %s", command[0], err, strings.TrimSpace(stderr.String()))
	}
	return starlark.String(strings.TrimSpace(string(output))), nil
}

func (h *Harness) proxyDetails() (starlark.Value, error) {
	values := map[string]string{
		"http":          "http://" + h.httpAddr,
		"https":         "https://" + h.httpsAddr,
		"cert":          h.certPath,
		"google_adc":    h.googleADCPath,
		"aws_config":    h.awsConfigPath,
		"gcloud_config": h.root + "/gcloud",
		"azure_config":  h.root + "/azure",
	}
	for name, listener := range h.listeners {
		values[name] = listener.Addr
	}
	result := starlark.NewDict(len(values))
	for key, value := range values {
		if err := result.SetKey(starlark.String(key), starlark.String(value)); err != nil {
			return nil, err
		}
	}
	return result, nil
}
