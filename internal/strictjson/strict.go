// Package strictjson rejects JSON that encoding/json would silently repair or
// interpret ambiguously. User text must never change during wire decoding.
package strictjson

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

func Valid(data []byte) bool {
	if !utf8.Valid(data) || !json.Valid(data) {
		return false
	}
	// JSON syntax is known valid here. Inspect escapes before decoding replaces
	// unpaired UTF-16 surrogates with U+FFFD.
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if data[i] != 'u' {
			continue
		}
		n, _ := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		i += 4
		if n >= 0xDC00 && n <= 0xDFFF {
			return false
		}
		if n >= 0xD800 && n <= 0xDBFF {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if !value(d, 0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func value(d *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	t, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		keys := make(map[string]bool)
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return false
			}
			key, ok := k.(string)
			if !ok || keys[key] {
				return false
			}
			keys[key] = true
			if !value(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for d.More() {
			if !value(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}
