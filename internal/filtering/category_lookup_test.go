package filtering

import (
	"fmt"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/urlfilter/rules"
)

func TestReportingCategoryForLists(t *testing.T) {
	lists := []FilterYAML{
		{Filter: Filter{ID: 10}, Category: CategoryDefault},
		{Filter: Filter{ID: 20}, Category: CategoryParental},
		{Filter: Filter{ID: 30}, Category: CategorySecurity},
	}
	cases := []struct {
		name string
		ids  []rulelist.APIID
		want FilterCategory
	}{
		{"no rules", nil, CategoryDefault},
		{"unknown list", []rulelist.APIID{99}, CategoryDefault},
		{"default", []rulelist.APIID{10}, CategoryDefault},
		{"parental", []rulelist.APIID{20}, CategoryParental},
		{"security", []rulelist.APIID{30}, CategorySecurity},
		{"parental over default", []rulelist.APIID{10, 20}, CategoryParental},
		{"security over parental", []rulelist.APIID{20, 30}, CategorySecurity},
		{"security before parental", []rulelist.APIID{30, 20}, CategorySecurity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := make([]*ResultRule, 0, len(tc.ids))
			for _, id := range tc.ids {
				rules = append(rules, &ResultRule{FilterListID: id})
			}
			if got := reportingCategoryForLists(rules, lists); got != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}

func BenchmarkReportingCategoryForLists(b *testing.B) {
	for _, count := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("lists=%d", count), func(b *testing.B) {
			lists := make([]FilterYAML, count)
			for i := range lists {
				lists[i].ID = rules.ListID(i + 1)
				lists[i].Category = CategoryDefault
			}
			lists[count-1].Category = CategoryParental
			applied := []*ResultRule{{FilterListID: rulelist.APIID(count)}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = reportingCategoryForLists(applied, lists)
			}
		})
	}
}
