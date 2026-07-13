package subscription

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

type entryRange struct {
	start     int
	end       int
	oversized bool
	indent    int
}

type boundedJSONScanner struct {
	content   []byte
	position  int
	outbounds []entryRange
}

func scanSingBoxEntries(content []byte) ([]entryRange, error) {
	if !json.Valid(content) {
		return nil, errMalformedDocument
	}
	scanner := &boundedJSONScanner{content: content}
	scanner.skipWhitespace()
	if scanner.peek() != '{' {
		return nil, errMalformedDocument
	}
	if err := scanner.parseObject(0, true); err != nil {
		return nil, err
	}
	scanner.skipWhitespace()
	if scanner.position != len(content) {
		return nil, errMalformedDocument
	}
	return scanner.outbounds, nil
}

func (scanner *boundedJSONScanner) parseValue(depth int) error {
	scanner.skipWhitespace()
	if scanner.position >= len(scanner.content) {
		return errMalformedDocument
	}
	switch scanner.content[scanner.position] {
	case '{':
		return scanner.parseObject(depth, false)
	case '[':
		return scanner.parseArray(depth)
	case '"':
		_, err := scanner.parseString(false)
		return err
	default:
		for scanner.position < len(scanner.content) {
			switch scanner.content[scanner.position] {
			case ',', '}', ']', ' ', '\t', '\r', '\n':
				return nil
			default:
				scanner.position++
			}
		}
		return nil
	}
}

func (scanner *boundedJSONScanner) parseObject(depth int, topLevel bool) error {
	if depth >= maxJSONNestingDepth || scanner.peek() != '{' {
		return errMalformedDocument
	}
	scanner.position++
	scanner.skipWhitespace()
	if scanner.peek() == '}' {
		scanner.position++
		return nil
	}
	keys := make(map[string]struct{})
	for members := 0; ; members++ {
		if members >= MaxEntries {
			return errMalformedDocument
		}
		key, err := scanner.parseString(true)
		if err != nil {
			return err
		}
		folded := foldJSONKey(key)
		if _, duplicate := keys[folded]; duplicate {
			return errMalformedDocument
		}
		keys[folded] = struct{}{}
		scanner.skipWhitespace()
		if scanner.peek() != ':' {
			return errMalformedDocument
		}
		scanner.position++
		scanner.skipWhitespace()
		if topLevel && strings.EqualFold(key, "outbounds") {
			if err := scanner.parseOutbounds(depth + 1); err != nil {
				return err
			}
		} else if err := scanner.parseValue(depth + 1); err != nil {
			return err
		}
		scanner.skipWhitespace()
		switch scanner.peek() {
		case ',':
			scanner.position++
			scanner.skipWhitespace()
		case '}':
			scanner.position++
			return nil
		default:
			return errMalformedDocument
		}
	}
}

func (scanner *boundedJSONScanner) parseArray(depth int) error {
	if depth >= maxJSONNestingDepth || scanner.peek() != '[' {
		return errMalformedDocument
	}
	scanner.position++
	scanner.skipWhitespace()
	if scanner.peek() == ']' {
		scanner.position++
		return nil
	}
	for entries := 0; ; entries++ {
		if entries >= MaxEntries {
			return errMalformedDocument
		}
		if err := scanner.parseValue(depth + 1); err != nil {
			return err
		}
		scanner.skipWhitespace()
		switch scanner.peek() {
		case ',':
			scanner.position++
			scanner.skipWhitespace()
		case ']':
			scanner.position++
			return nil
		default:
			return errMalformedDocument
		}
	}
}

func (scanner *boundedJSONScanner) parseOutbounds(depth int) error {
	if depth >= maxJSONNestingDepth || scanner.peek() != '[' {
		return errMalformedDocument
	}
	scanner.position++
	scanner.skipWhitespace()
	if scanner.peek() == ']' {
		scanner.position++
		return nil
	}
	for entry := 0; ; entry++ {
		if entry >= MaxEntries {
			return errTooManyEntries
		}
		start := scanner.position
		if err := scanner.parseValue(depth + 1); err != nil {
			return err
		}
		end := scanner.position
		scanner.outbounds = append(scanner.outbounds, entryRange{start: start, end: end, oversized: end-start > MaxEntryBytes})
		scanner.skipWhitespace()
		switch scanner.peek() {
		case ',':
			scanner.position++
			scanner.skipWhitespace()
		case ']':
			scanner.position++
			return nil
		default:
			return errMalformedDocument
		}
	}
}

func (scanner *boundedJSONScanner) parseString(decode bool) (string, error) {
	if scanner.peek() != '"' {
		return "", errMalformedDocument
	}
	start := scanner.position
	scanner.position++
	for scanner.position < len(scanner.content) {
		switch scanner.content[scanner.position] {
		case '\\':
			scanner.position += 2
		case '"':
			scanner.position++
			if !decode {
				return "", nil
			}
			raw := scanner.content[start:scanner.position]
			if len(raw) > MaxEntryBytes {
				return "", errMalformedDocument
			}
			value, err := strconv.Unquote(string(raw))
			if err != nil {
				return "", errMalformedDocument
			}
			return value, nil
		default:
			scanner.position++
		}
	}
	return "", errMalformedDocument
}

func (scanner *boundedJSONScanner) skipWhitespace() {
	for scanner.position < len(scanner.content) {
		switch scanner.content[scanner.position] {
		case ' ', '\t', '\r', '\n':
			scanner.position++
		default:
			return
		}
	}
}

func (scanner *boundedJSONScanner) peek() byte {
	if scanner.position >= len(scanner.content) {
		return 0
	}
	return scanner.content[scanner.position]
}

func scanClashEntries(content []byte) ([]entryRange, error) {
	var entries []entryRange
	proxiesFound := false
	proxiesEnded := false
	entryStart := -1
	entryIndent := -1
	entryCount := 0
	lineStart := 0
	documentMarkers := 0
	for lineStart <= len(content) {
		lineEnd := bytes.IndexByte(content[lineStart:], '\n')
		if lineEnd < 0 {
			lineEnd = len(content)
		} else {
			lineEnd += lineStart
		}
		line := bytes.TrimSuffix(content[lineStart:lineEnd], []byte{'\r'})
		trimmed := bytes.TrimSpace(line)
		indent := leadingYAMLIndent(line)
		if bytes.Equal(trimmed, []byte("---")) {
			documentMarkers++
			if documentMarkers > 1 || proxiesFound {
				return nil, errMalformedDocument
			}
		}
		if !proxiesFound && indent == 0 && isProxiesDeclaration(trimmed) {
			proxiesFound = true
		} else if proxiesFound && !proxiesEnded && len(trimmed) != 0 && trimmed[0] != '#' {
			if indent == 0 {
				if entryStart >= 0 {
					entries = appendClashEntry(entries, entryStart, lineStart, entryIndent)
					entryStart = -1
				}
				proxiesEnded = true
			} else if isYAMLSequenceEntry(line, indent) {
				if entryIndent < 0 {
					entryIndent = indent
				}
				if indent == entryIndent {
					entryCount++
					if entryCount > MaxEntries {
						return nil, errTooManyEntries
					}
					if entryStart >= 0 {
						entries = appendClashEntry(entries, entryStart, lineStart, entryIndent)
					}
					entryStart = lineStart
				}
			} else if entryStart < 0 {
				return nil, errMalformedDocument
			}
		}
		if lineEnd == len(content) {
			break
		}
		lineStart = lineEnd + 1
	}
	if entryStart >= 0 {
		entries = appendClashEntry(entries, entryStart, len(content), entryIndent)
	}
	if !proxiesFound {
		return nil, errMalformedDocument
	}
	for _, entry := range entries {
		if !entry.oversized && !validYAMLDepth(content[entry.start:entry.end], entry.indent) {
			return nil, errMalformedDocument
		}
	}
	return entries, nil
}

func isProxiesDeclaration(trimmed []byte) bool {
	if !bytes.HasPrefix(trimmed, []byte("proxies:")) {
		return false
	}
	remainder := bytes.TrimSpace(trimmed[len("proxies:"):])
	return len(remainder) == 0 || remainder[0] == '#'
}

func appendClashEntry(entries []entryRange, start, end, indent int) []entryRange {
	return append(entries, entryRange{start: start, end: end, indent: indent, oversized: end-start > MaxEntryBytes})
}

func leadingYAMLIndent(line []byte) int {
	indent := 0
	for indent < len(line) && line[indent] == ' ' {
		indent++
	}
	return indent
}

func isYAMLSequenceEntry(line []byte, indent int) bool {
	if indent >= len(line) || line[indent] != '-' {
		return false
	}
	return indent+1 == len(line) || line[indent+1] == ' ' || line[indent+1] == '\t'
}

func validYAMLDepth(entry []byte, baseIndent int) bool {
	for remaining := entry; len(remaining) > 0; {
		lineEnd := bytes.IndexByte(remaining, '\n')
		line := remaining
		if lineEnd >= 0 {
			line = remaining[:lineEnd]
			remaining = remaining[lineEnd+1:]
		} else {
			remaining = nil
		}
		if len(bytes.TrimSpace(line)) != 0 && leadingYAMLIndent(line)-baseIndent > maxJSONNestingDepth*2 {
			return false
		}
	}

	flowDepth := 0
	quote := byte(0)
	escaped := false
	for index := 0; index < len(entry); index++ {
		character := entry[index]
		if quote != 0 {
			if quote == '"' && character == '\\' && !escaped {
				escaped = true
				continue
			}
			if quote == '\'' && character == '\'' && index+1 < len(entry) && entry[index+1] == '\'' {
				index++
				continue
			}
			if character == quote && !escaped {
				quote = 0
			}
			escaped = false
			continue
		}
		switch character {
		case '\'', '"':
			quote = character
		case '#':
			for index < len(entry) && entry[index] != '\n' {
				index++
			}
		case '[', '{':
			flowDepth++
			if flowDepth > maxJSONNestingDepth {
				return false
			}
		case ']', '}':
			flowDepth--
			if flowDepth < 0 {
				return false
			}
		}
	}
	return flowDepth == 0 && quote == 0
}

func dedentYAMLEntry(entry []byte, indent int) []byte {
	output := make([]byte, 0, len(entry))
	for len(entry) > 0 {
		lineEnd := bytes.IndexByte(entry, '\n')
		line := entry
		newline := false
		if lineEnd >= 0 {
			line = entry[:lineEnd]
			entry = entry[lineEnd+1:]
			newline = true
		} else {
			entry = nil
		}
		remove := min(indent, leadingYAMLIndent(line))
		output = append(output, line[remove:]...)
		if newline {
			output = append(output, '\n')
		}
	}
	return output
}
