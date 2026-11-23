package filtering

import "testing"

func TestFilterCategoryEffective(t *testing.T) {
	tests := []struct {
		in, want FilterCategory
	}{
		{"", CategoryDefault},
		{CategoryDefault, CategoryDefault},
		{CategorySecurity, CategorySecurity},
		{CategoryParental, CategoryParental},
	}

	for _, tt := range tests {
		if got := tt.in.Effective(); got != tt.want {
			t.Errorf("%q.Effective() = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestValidateFilterCategory(t *testing.T) {
	for _, tc := range []struct {
		name      string
		category  FilterCategory
		allowlist bool
		wantErr   bool
	}{
		{"legacy config", "", false, false},
		{"default", CategoryDefault, false, false},
		{"security", CategorySecurity, false, false},
		{"parental", CategoryParental, false, false},
		{"invalid", "other", false, true},
		{"default allowlist", "", true, false},
		{"security allowlist", CategorySecurity, true, true},
		{"parental allowlist", CategoryParental, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFilterCategory(tc.category, tc.allowlist)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateFilterCategory(%q, %t) error = %v, wantErr %t", tc.category, tc.allowlist, err, tc.wantErr)
			}
		})
	}
}
