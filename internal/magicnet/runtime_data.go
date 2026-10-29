package magicnet

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func rtMap(v any) M {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}
func rtArray(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}
func rtString(v any) string { s, _ := v.(string); return s }
func rtBool(v any) bool     { b, _ := v.(bool); return b }
func rtInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		x, e := n.Int64()
		return x, e == nil
	case float64:
		if n >= -9007199254740991 && n <= 9007199254740991 && n == float64(int64(n)) {
			return int64(n), true
		}
	}
	return 0, false
}
func rtClone(v any) any {
	b, _ := json.Marshal(v)
	var o any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	_ = d.Decode(&o)
	return o
}
func rtEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func rtJSON(v any) []byte { b, _ := json.MarshalIndent(v, "", "  "); return append(b, '\n') }
func rtStrings(a []string) []any {
	out := make([]any, len(a))
	for i, s := range a {
		out[i] = s
	}
	return out
}
func rtStringList(v any) ([]string, bool) {
	if s, ok := v.(string); ok {
		return []string{s}, true
	}
	if a, ok := v.([]string); ok {
		return a, true
	}
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(a))
	for i, x := range a {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// DecodeJSON rejects duplicate object keys, trailing JSON and excessive nesting.
// Silent last-key-wins decoding is unsafe for revision and credential fields.
func rtDecodeJSON(data []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var parse func(int) (any, error)
	parse = func(depth int) (any, error) {
		if depth > 64 {
			return nil, fmt.Errorf("JSON nesting limit exceeded")
		}
		t, e := d.Token()
		if e != nil {
			return nil, e
		}
		switch v := t.(type) {
		case json.Delim:
			switch v {
			case '{':
				m := M{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return nil, e
					}
					key, ok := k.(string)
					if !ok {
						return nil, fmt.Errorf("invalid key")
					}
					if _, ok := m[key]; ok {
						return nil, fmt.Errorf("duplicate key")
					}
					value, e := parse(depth + 1)
					if e != nil {
						return nil, e
					}
					m[key] = value
				}
				_, e := d.Token()
				return m, e
			case '[':
				a := []any{}
				for d.More() {
					v, e := parse(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
					if len(a) > 100000 {
						return nil, fmt.Errorf("JSON array limit exceeded")
					}
				}
				_, e := d.Token()
				return a, e
			}
			return nil, fmt.Errorf("unexpected delimiter")
		default:
			return t, nil
		}
	}
	v, e := parse(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	return v, nil
}

func rtBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := encoding.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, E("subscription.input_invalid", "Invalid base64 encoding")
}

func rtParseInt(v any) (int64, error) {
	if n, ok := rtInt(v); ok {
		return n, nil
	}
	if s, ok := v.(string); ok {
		n, e := strconv.ParseInt(s, 10, 64)
		if e == nil {
			return n, nil
		}
	}
	return 0, fmt.Errorf("invalid integer")
}

func rtAllowedKeys(m M, names string) bool {
	allowed := map[string]bool{}
	for _, k := range strings.Fields(names) {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return false
		}
	}
	return true
}
