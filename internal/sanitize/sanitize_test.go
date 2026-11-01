
package sanitize

import (
	"strings"
	"testing"
)

func TestSanitizeText(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		maxLen          int
		keepFormatting  bool
		want            string
		wantErr         bool
	}{
		{"valid text", "Hello World", 512, false, "Hello World", false},
		{"trim whitespace", "  Hello  ", 512, false, "Hello", false},
		{"empty input", "   ", 512, false, "", true},
		{"too long", "Hello World", 5, false, "", true},
		{"null byte", "Hello\x00World", 512, false, "", true},
		{"newline rejected", "Hello\nWorld", 512, false, "", true},
		{"newline allowed", "Hello\nWorld", 512, true, "Hello\nWorld", false},
		{"tab allowed", "Hello\tWorld", 512, true, "Hello\tWorld", false},
		{"invalid utf8", string([]byte{0xff, 0xfe}), 512, false, "", true},
		{"unicode text", "سلام دنیا", 512, false, "سلام دنیا", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeText(tt.input, tt.maxLen, tt.keepFormatting)

			if (err != nil) != tt.wantErr {
				t.Fatalf("SanitizeText() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("SanitizeText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"valid label", "my-label", "my-label", false},
		{"valid unicode", "برچسب", "برچسب", false},
		{"empty label", "", "", true},
		{"too long", strings.Repeat("a", MaxLabelLen+1), "", true},
		{"shell characters", "test;rm", "", true},
		{"angle brackets", "test<value>", "", true},
		{"backslash", "test\\value", "", true},
		{"path separator", "folder/file", "", true},
		{"path traversal", "../secret", "", true},
		{"double dots", "my..label", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeLabel(tt.input)

			if (err != nil) != tt.wantErr {
				t.Fatalf("SanitizeLabel() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("SanitizeLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeAppName(t *testing.T) {
	allowlist := map[string]struct{}{
		"my-app":     {},
		"anotherapp": {},
	}

	tests := []struct {
		name    string
		input   string
		allow   map[string]struct{}
		want    string
		wantErr bool
	}{
		{"valid app name", "my-app", nil, "my-app", false},
		{"valid with allowlist", "my-app", allowlist, "my-app", false},
		{"case insensitive allowlist", "MY-APP", allowlist, "MY-APP", false},
		{"not in allowlist", "unknown-app", allowlist, "", true},
		{"invalid characters", "my app", nil, "", true},
		{"slash rejected", "my/app", nil, "", true},
		{"empty name", "", nil, "", true},
		{"too long", strings.Repeat("a", MaxAppNameLen+1), nil, "", true},
		{"valid underscore", "my_app", nil, "my_app", false},
		{"valid dot", "my.app", nil, "my.app", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeAppName(tt.input, tt.allow)

			if (err != nil) != tt.wantErr {
				t.Fatalf("SanitizeAppName() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("SanitizeAppName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeAbsolutePath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		roots   []string
		want    string
		wantErr bool
	}{
		{"valid absolute path", "/home/user/file.txt", nil, "/home/user/file.txt", false},
		{"normalized path", "/home/user/../user/file.txt", nil, "/home/user/file.txt", false},
		{"relative path rejected", "home/user/file.txt", nil, "", true},
		{"empty path", "", nil, "", true},
		{"path inside allowed root", "/home/user/data/file.txt", []string{"/home/user/data"}, "/home/user/data/file.txt", false},
		{"path outside allowed root", "/etc/passwd", []string{"/home/user/data"}, "", true},
		{"root itself", "/home/user/data", []string{"/home/user/data"}, "/home/user/data", false},
		{"similar prefix rejected", "/home/user/database/file.txt", []string{"/home/user/data"}, "", true},
		{"invalid root ignored", "/etc/passwd", []string{"relative/root"}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeAbsolutePath(tt.input, tt.roots)

			if (err != nil) != tt.wantErr {
				t.Fatalf("SanitizeAbsolutePath() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("SanitizeAbsolutePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeSafeRelativePath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		maxLen  int
		allowDot bool
		want    string
		wantErr bool
	}{
		{"valid relative path", "documents/file.txt", 4096, false, "documents/file.txt", false},
		{"normalized path", "documents/./file.txt", 4096, false, "documents/file.txt", false},
		{"parent traversal", "../secret", 4096, false, "", true},
		{"nested traversal", "documents/../../secret", 4096, false, "", true},
		{"absolute path", "/etc/passwd", 4096, false, "", true},
		{"dot rejected", ".", 4096, false, "", true},
		{"dot allowed", ".", 4096, true, ".", false},
		{"empty input", "", 4096, false, "", true},
		{"too long", "documents/file.txt", 5, false, "", true},
		{"shell characters", "documents/file;txt", 4096, false, "", true},
		{"backtick rejected", "documents/`file`", 4096, false, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeSafeRelativePath(tt.input, tt.maxLen, tt.allowDot)

			if (err != nil) != tt.wantErr {
				t.Fatalf("SanitizeSafeRelativePath() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("SanitizeSafeRelativePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeOpenerCommand(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"valid command", "firefox", "firefox", false},
		{"valid command with hyphen", "google-chrome", "google-chrome", false},
		{"valid command with underscore", "my_command", "my_command", false},
		{"valid command with dot", "python3.12", "python3.12", false},
		{"empty command", "", "", true},
		{"command with arguments", "firefox --private", "", true},
		{"absolute path", "/usr/bin/firefox", "", true},
		{"shell injection", "firefox;rm", "", true},
		{"command substitution", "$(whoami)", "", true},
		{"quoted command", "'firefox'", "", true},
		{"too long", strings.Repeat("a", MaxGenericLen+1), "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeOpenerCommand(tt.input)

			if (err != nil) != tt.wantErr {
				t.Fatalf("SanitizeOpenerCommand() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("SanitizeOpenerCommand() = %q, want %q", got, tt.want)
			}
		})
	}
}

