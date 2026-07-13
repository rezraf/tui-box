package terminaltext

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const replacementRune = '�'

func IsSafeRune(character rune) bool {
	if !utf8.ValidRune(character) || unicode.IsControl(character) || unicode.Is(unicode.Cf, character) ||
		unicode.Is(unicode.Zl, character) || unicode.Is(unicode.Zp, character) {
		return false
	}
	return unicode.IsGraphic(character)
}

func Valid(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if !IsSafeRune(character) {
			return false
		}
	}
	return true
}

func Sanitize(value string) string {
	if Valid(value) {
		return value
	}
	var output strings.Builder
	output.Grow(len(value))
	for len(value) > 0 {
		character, size := utf8.DecodeRuneInString(value)
		if character == utf8.RuneError && size == 1 {
			output.WriteRune(replacementRune)
			value = value[1:]
			continue
		}
		if IsSafeRune(character) {
			output.WriteRune(character)
		} else {
			output.WriteRune(replacementRune)
		}
		value = value[size:]
	}
	return output.String()
}
