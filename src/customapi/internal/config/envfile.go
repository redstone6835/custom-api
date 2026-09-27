package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadEnvFile reads a KEY=VALUE file and returns the pairs.
//
// This exists so that a FreeBSD rc.d script can keep upstream credentials out
// of the world-readable configuration file without relying on shell sourcing,
// which silently fails across the daemon(8) boundary and cannot express
// variable names that are not valid shell identifiers.
//
// The accepted syntax is deliberately small and strict:
//
//	# comment
//	CUSTOMS_CHANNEL_UPSTREAM_A_APIKEY=sk-...
//	QUOTED="value with spaces"
//	EMPTY=
//
// A line that is not a comment, blank, or a KEY=VALUE assignment is an error
// rather than being ignored, so a malformed secrets file cannot silently leave
// a channel without credentials.
func LoadEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open env file %s: %w", path, err)
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("config: %s:%d: expected KEY=VALUE, got %q", path, lineNo, line)
		}
		key = strings.TrimSpace(key)
		// Some secrets contain an '=' themselves, so only the first one
		// separates key from value.
		value = strings.TrimSpace(value)
		if key == "" {
			return nil, fmt.Errorf("config: %s:%d: empty key", path, lineNo)
		}
		for i, r := range key {
			valid := r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9')
			if !valid {
				return nil, fmt.Errorf("config: %s:%d: invalid key %q", path, lineNo, key)
			}
		}
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		out[key] = value
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("config: read env file %s: %w", path, err)
	}
	return out, nil
}

// ApplyEnvPairs overlays KEY=VALUE pairs onto the configuration, using the same
// naming convention as ApplyEnv.
func (c *Config) ApplyEnvPairs(pairs map[string]string) {
	environ := make([]string, 0, len(pairs))
	for k, v := range pairs {
		environ = append(environ, k+"="+v)
	}
	c.applyEnv(environ)
}
