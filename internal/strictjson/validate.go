package strictjson

import (
	"encoding/json"
	"errors"
	"io"
	"unicode"
	"unicode/utf8"
)

const maxNestingDepth = 100

var errInvalid = errors.New("JSON document is invalid")

type KeyComparison uint8

const (
	ExactKeys KeyComparison = iota
	FoldedKeys
)

func ValidateUniqueObjectFields(reader io.Reader, comparison KeyComparison) error {
	if comparison != ExactKeys && comparison != FoldedKeys {
		return errInvalid
	}
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	if err := validateValue(decoder, comparison, 0); err != nil {
		return errInvalid
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalid
	}
	return nil
}

func validateValue(decoder *json.Decoder, comparison KeyComparison, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	if depth >= maxNestingDepth {
		return errInvalid
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errInvalid
			}
			identity := key
			if comparison == FoldedKeys {
				identity = foldName(key)
			}
			if _, duplicate := seen[identity]; duplicate {
				return errInvalid
			}
			seen[identity] = struct{}{}
			if err := validateValue(decoder, comparison, depth+1); err != nil {
				return err
			}
		}
		return requireDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := validateValue(decoder, comparison, depth+1); err != nil {
				return err
			}
		}
		return requireDelimiter(decoder, ']')
	default:
		return errInvalid
	}
}

func foldName(value string) string {
	folded := make([]byte, 0, len(value))
	for index := 0; index < len(value); {
		if character := value[index]; character < utf8.RuneSelf {
			if 'a' <= character && character <= 'z' {
				character -= 'a' - 'A'
			}
			folded = append(folded, character)
			index++
			continue
		}
		character, size := utf8.DecodeRuneInString(value[index:])
		folded = utf8.AppendRune(folded, foldRune(character))
		index += size
	}
	return string(folded)
}

func foldRune(character rune) rune {
	for {
		folded := unicode.SimpleFold(character)
		if folded <= character {
			return folded
		}
		character = folded
	}
}

func requireDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != expected {
		return errInvalid
	}
	return nil
}
