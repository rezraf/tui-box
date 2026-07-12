package subscription

import (
	"bytes"
	"encoding/json"
	"io"
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
			if _, duplicate := keys[key]; duplicate {
				return errInvalidEntry
			}
			keys[key] = struct{}{}
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
