package subscription

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode"
)

const maxJSONNestingDepth = 100

func validateStrictJSON(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, 0); err != nil {
		return errInvalidEntry
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errInvalidEntry
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	if depth >= maxJSONNestingDepth {
		return errInvalidEntry
	}

	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errInvalidEntry
			}
			foldedKey := foldJSONKey(key)
			if _, duplicate := keys[foldedKey]; duplicate {
				return errInvalidEntry
			}
			keys[foldedKey] = struct{}{}
			if err := validateJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		return requireJSONDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		return requireJSONDelimiter(decoder, ']')
	default:
		return errInvalidEntry
	}
}

func foldJSONKey(key string) string {
	var folded strings.Builder
	folded.Grow(len(key))
	for _, character := range key {
		if 'a' <= character && character <= 'z' {
			character -= 'a' - 'A'
		} else if character > unicode.MaxASCII {
			character = foldJSONRune(character)
		}
		folded.WriteRune(character)
	}
	return folded.String()
}

func foldJSONRune(character rune) rune {
	for {
		folded := unicode.SimpleFold(character)
		if folded <= character {
			return folded
		}
		character = folded
	}
}

func requireJSONDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != expected {
		return errInvalidEntry
	}
	return nil
}
