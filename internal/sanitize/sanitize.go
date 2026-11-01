
package sanitize

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Max lengths for production safety.
const (
	MaxGenericLen = 512
	MaxLabelLen   = 128
	MaxAppNameLen = 64
	MaxPathLen    = 4096
)

// ValidationError is a lightweight typed error.
type ValidationError struct {
	Field string
	Msg   string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Msg)
}

// SanitizeText trims whitespace, validates UTF-8 and length,
// and rejects control characters except newline/tab when formatting is enabled.
func SanitizeText(s string, maxLen int, keepFormatting bool) (string, error) {
	s = strings.TrimSpace(s)

	if s == "" {
		return "", errors.New("empty")
	}
	if len(s) > maxLen {
		return "", errors.New("too long")
	}
	if !utf8.ValidString(s) {
		return "", errors.New("invalid utf-8")
	}

	for _, r := range s {
		if unicode.IsControl(r) {
			if keepFormatting && (r == '\n' || r == '\t') {
				continue
			}
			return "", errors.New("contains control character")
		}
	}

	return s, nil
}

// SanitizeLabel validates a simple, predictable label.
func SanitizeLabel(s string) (string, error) {
	s, err := SanitizeText(s, MaxLabelLen, false)
	if err != nil {
		return "", err
	}

	const banned = "<>{}`$;&|\\"
	if strings.ContainsAny(s, banned) {
		return "", errors.New("contains disallowed characters")
	}

	if strings.Contains(s, "/") || strings.Contains(s, "..") {
		return "", errors.New("looks like a path")
	}

	return s, nil
}

// SanitizeAppName validates an application name and optionally enforces an allowlist.
func SanitizeAppName(s string, allow map[string]struct{}) (string, error) {
	s, err := SanitizeText(s, MaxAppNameLen, false)
	if err != nil {
		return "", &ValidationError{Field: "app_name", Msg: err.Error()}
	}

	for _, r := range s {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == '.' {
			continue
		}

		return "", &ValidationError{
			Field: "app_name",
			Msg:   "contains invalid characters",
		}
	}

	if len(allow) > 0 {
		if _, ok := allow[strings.ToLower(s)]; !ok {
			return "", &ValidationError{
				Field: "app_name",
				Msg:   "not in allowlist",
			}
		}
	}

	return s, nil
}

// SanitizeAbsolutePath validates an absolute path against allowed roots.
func SanitizeAbsolutePath(s string, allowedRoots []string) (string, error) {
	s, err := SanitizeText(s, MaxPathLen, false)
	if err != nil {
		return "", err
	}

	clean := filepath.Clean(s)

	if !filepath.IsAbs(clean) {
		return "", errors.New("not absolute path")
	}

	if len(allowedRoots) > 0 {
		ok := false

		for _, root := range allowedRoots {
			root = filepath.Clean(strings.TrimSpace(root))

			if root == "" || !filepath.IsAbs(root) {
				continue
			}

			if clean == root ||
				strings.HasPrefix(clean, root+string(filepath.Separator)) {
				ok = true
				break
			}
		}

		if !ok {
			return "", errors.New("outside allowed roots")
		}
	}

	return clean, nil
}

// SanitizeSafeRelativePath validates a relative path and prevents traversal.
func SanitizeSafeRelativePath(s string, maxLen int, allowDot bool) (string, error) {
	s, err := SanitizeText(s, maxLen, false)
	if err != nil {
		return "", err
	}

	clean := filepath.Clean(s)

	if filepath.IsAbs(clean) {
		return "", errors.New("must be relative path")
	}

	if clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("path traversal")
	}

	if !allowDot && (clean == "." || clean == "") {
		return "", errors.New("invalid relative path")
	}

	const banned = "<>|`$;&\x00"
	if strings.ContainsAny(clean, banned) {
		return "", errors.New("contains disallowed characters")
	}

	return clean, nil
}

// SanitizeOpenerCommand validates a bare executable name without arguments.
func SanitizeOpenerCommand(s string) (string, error) {
	s, err := SanitizeText(s, MaxGenericLen, false)
	if err != nil {
		return "", err
	}

	if strings.ContainsAny(s, " \t/\\'\"`$;&|<>") {
		return "", errors.New("only bare command name allowed")
	}

	for _, r := range s {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == '.' {
			continue
		}

		return "", errors.New("contains invalid characters")
	}

	return s, nil
}

