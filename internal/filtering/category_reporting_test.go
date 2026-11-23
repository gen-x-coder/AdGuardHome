package filtering

import (
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"testing"
)

func TestCategoryForRules(t *testing.T) {
	cases := []struct {
		name       string
		ids        []rulelist.APIID
		categories map[rulelist.APIID]FilterCategory
		want       FilterCategory
	}{
		{"no rules", nil, nil, CategoryDefault},
		{"unknown ID", []rulelist.APIID{3}, nil, CategoryDefault},
		{"default", []rulelist.APIID{3}, map[rulelist.APIID]FilterCategory{3: CategoryDefault}, CategoryDefault},
		{"security", []rulelist.APIID{3}, map[rulelist.APIID]FilterCategory{3: CategorySecurity}, CategorySecurity},
		{"parental", []rulelist.APIID{3}, map[rulelist.APIID]FilterCategory{3: CategoryParental}, CategoryParental},
		{"parental over default", []rulelist.APIID{1, 2}, map[rulelist.APIID]FilterCategory{1: CategoryDefault, 2: CategoryParental}, CategoryParental},
		{"security over parental", []rulelist.APIID{1, 2}, map[rulelist.APIID]FilterCategory{1: CategoryParental, 2: CategorySecurity}, CategorySecurity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := make([]*ResultRule, 0, len(tc.ids))
			for _, id := range tc.ids {
				rules = append(rules, &ResultRule{FilterListID: id})
			}
			if got := categoryForRules(rules, tc.categories); got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}
