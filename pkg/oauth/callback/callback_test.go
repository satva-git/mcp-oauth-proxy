package callback

import "testing"

func TestEmailDomainAllowed(t *testing.T) {
	satva := []string{"satvasolutions.com", "synctools.ai"}

	tests := []struct {
		name    string
		email   string
		allowed []string
		want    bool
	}{
		{"empty allow-list permits anyone", "someone@gmail.com", nil, true},
		{"exact domain match", "chintan@satvasolutions.com", satva, true},
		{"second domain in list", "tanmay@synctools.ai", satva, true},
		{"case-insensitive domain", "USER@SatvaSolutions.COM", satva, true},
		{"case-insensitive allow-list entry", "user@example.com", []string{"EXAMPLE.COM"}, true},
		{"whitespace around allow-list entry", "user@example.com", []string{" example.com "}, true},
		{"outside domain rejected", "attacker@gmail.com", satva, false},
		{"empty email rejected", "", satva, false},
		{"malformed email without @ rejected", "notanemail", satva, false},
		{"empty domain rejected", "user@", satva, false},
		// A suffix match would wrongly admit these; the check must be exact.
		{"lookalike suffix domain rejected", "user@evilsatvasolutions.com", satva, false},
		{"subdomain not implied by parent", "user@mail.satvasolutions.com", satva, false},
		// The local part must never be able to spoof the domain.
		{"domain taken from last @, not first", "satvasolutions.com@gmail.com", satva, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := emailDomainAllowed(tt.email, tt.allowed); got != tt.want {
				t.Errorf("emailDomainAllowed(%q, %v) = %v, want %v", tt.email, tt.allowed, got, tt.want)
			}
		})
	}
}
