package cmd

import (
	"reflect"
	"testing"
)

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty is nil (allow-list disabled)", "", nil},
		{"whitespace only is nil", "   ", nil},
		{"single domain", "satvasolutions.com", []string{"satvasolutions.com"}},
		{"two domains", "satvasolutions.com,synctools.ai", []string{"satvasolutions.com", "synctools.ai"}},
		{"spaces around entries", " satvasolutions.com , synctools.ai ", []string{"satvasolutions.com", "synctools.ai"}},
		{"trailing comma drops empty", "satvasolutions.com,", []string{"satvasolutions.com"}},
		{"lone comma yields nil, not an empty domain", ",", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitAndTrim(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitAndTrim(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}
