package filtering

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateFilterCategory(t *testing.T) {
	testCases := []struct {
		name        string
		category    FilterCategory
		isAllowlist bool
		wantErr     bool
	}{{
		name:        "legacy",
		category:    "",
		isAllowlist: false,
		wantErr:     false,
	}, {
		name:        "security",
		category:    CategorySecurity,
		isAllowlist: false,
		wantErr:     false,
	}, {
		name:        "parental",
		category:    CategoryParental,
		isAllowlist: false,
		wantErr:     false,
	}, {
		name:        "unknown",
		category:    "other",
		isAllowlist: false,
		wantErr:     true,
	}, {
		name:        "allowlist_default",
		category:    CategoryDefault,
		isAllowlist: true,
		wantErr:     false,
	}, {
		name:        "allowlist_security",
		category:    CategorySecurity,
		isAllowlist: true,
		wantErr:     true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFilterCategory(tc.category, tc.isAllowlist)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// newCategoryTestFilter returns a new *DNSFilter with disabled lists, so that
// nothing is downloaded: list 10 has no category, 20 is parental, 30 is
// security, and 40 has an invalid category.  Allowlist 50 is security, which
// is also invalid.
func newCategoryTestFilter(tb testing.TB) (d *DNSFilter) {
	tb.Helper()

	d, err := New(&Config{
		Logger:       testLogger,
		DataDir:      tb.TempDir(),
		HTTPReg:      aghhttp.EmptyRegistrar{},
		ConfModifier: &aghtest.ConfigModifier{OnApply: func(_ context.Context) {}},
		MaxHTTPSize:  testFilterSize,
		Filters: []FilterYAML{{
			URL:    "https://list10.example/",
			Filter: Filter{ID: 10},
		}, {
			URL:      "https://list20.example/",
			Category: CategoryParental,
			Filter:   Filter{ID: 20},
		}, {
			URL:      "https://list30.example/",
			Category: CategorySecurity,
			Filter:   Filter{ID: 30},
		}, {
			URL:      "https://list40.example/",
			Category: "invalid",
			Filter:   Filter{ID: 40},
		}},
		WhitelistFilters: []FilterYAML{{
			URL:      "https://allow50.example/",
			Category: CategorySecurity,
			Filter:   Filter{ID: 50},
		}},
	}, nil)
	require.NoError(tb, err)
	tb.Cleanup(d.Close)

	return d
}

// newBlockResult returns a result with reason and one rule for each list ID.
func newBlockResult(reason Reason, ids ...rulelist.APIID) (res *Result) {
	res = &Result{Reason: reason}
	for _, id := range ids {
		res.Rules = append(res.Rules, &ResultRule{FilterListID: id})
	}

	return res
}

func TestDNSFilter_ReportingCategory(t *testing.T) {
	d := newCategoryTestFilter(t)

	assert.Empty(t, d.conf.Filters[3].Category, "invalid category must be reset")
	assert.Empty(t, d.conf.WhitelistFilters[0].Category, "allowlist category must be reset")

	testCases := []struct {
		res  *Result
		name string
		want FilterCategory
	}{{
		res:  nil,
		name: "nil",
		want: CategoryDefault,
	}, {
		res:  newBlockResult(FilteredBlockList, 10),
		name: "default_list",
		want: CategoryDefault,
	}, {
		res:  newBlockResult(FilteredBlockList, 20),
		name: "parental_list",
		want: CategoryParental,
	}, {
		res:  newBlockResult(FilteredBlockList, 30),
		name: "security_list",
		want: CategorySecurity,
	}, {
		res:  newBlockResult(FilteredBlockList, 10, 20),
		name: "parental_over_default",
		want: CategoryParental,
	}, {
		res:  newBlockResult(FilteredBlockList, 20, 30),
		name: "security_over_parental",
		want: CategorySecurity,
	}, {
		res:  newBlockResult(FilteredBlockList, 30, 20),
		name: "security_first",
		want: CategorySecurity,
	}, {
		res:  newBlockResult(FilteredBlockList, 40),
		name: "reset_invalid",
		want: CategoryDefault,
	}, {
		res:  newBlockResult(FilteredBlockList, rulelist.APIIDCustom),
		name: "custom_rules",
		want: CategoryDefault,
	}, {
		res:  newBlockResult(FilteredBlockList, 99),
		name: "unknown_list",
		want: CategoryDefault,
	}, {
		res:  newBlockResult(NotFilteredAllowList, 50),
		name: "allowlist",
		want: CategoryDefault,
	}, {
		res:  newBlockResult(FilteredBlockedService, 30),
		name: "not_blocklist_reason",
		want: CategoryDefault,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, d.ReportingCategory(tc.res))
		})
	}
}

// setURL calls handleFilteringSetURL for a disabled list and returns the
// response.
func setURL(
	tb testing.TB,
	d *DNSFilter,
	listURL string,
	category FilterCategory,
	isAllowlist bool,
) (w *httptest.ResponseRecorder) {
	tb.Helper()

	data, err := json.Marshal(&filterURLReq{
		Data: &filterURLReqData{
			Name:     "list",
			URL:      listURL,
			Enabled:  false,
			Category: category,
		},
		URL:       listURL,
		Whitelist: isAllowlist,
	})
	require.NoError(tb, err)

	r := httptest.NewRequest(http.MethodPost, "http://example.org", bytes.NewReader(data))
	w = httptest.NewRecorder()
	d.handleFilteringSetURL(w, r)

	return w
}

func TestDNSFilter_handleFilteringSetURL_category(t *testing.T) {
	const (
		list20  = "https://list20.example/"
		allow50 = "https://allow50.example/"
	)

	d := newCategoryTestFilter(t)
	blocked := newBlockResult(FilteredBlockList, 20)

	t.Run("omitted_keeps", func(t *testing.T) {
		w := setURL(t, d, list20, "", false)
		require.Equal(t, http.StatusOK, w.Code)

		assert.Equal(t, CategoryParental, d.conf.Filters[1].Category)
		assert.Equal(t, CategoryParental, d.ReportingCategory(blocked))
	})

	t.Run("changed", func(t *testing.T) {
		w := setURL(t, d, list20, CategorySecurity, false)
		require.Equal(t, http.StatusOK, w.Code)

		assert.Equal(t, CategorySecurity, d.conf.Filters[1].Category)
		assert.Equal(t, CategorySecurity, d.ReportingCategory(blocked))
	})

	t.Run("invalid", func(t *testing.T) {
		w := setURL(t, d, list20, "other", false)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		assert.Equal(t, CategorySecurity, d.conf.Filters[1].Category)
	})

	t.Run("allowlist", func(t *testing.T) {
		w := setURL(t, d, allow50, CategoryParental, true)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		assert.Empty(t, d.conf.WhitelistFilters[0].Category)
	})
}

func TestDNSFilter_handleFilteringAddURL_category(t *testing.T) {
	d := newCategoryTestFilter(t)

	for _, req := range []filterAddJSON{{
		Name:     "invalid",
		URL:      "https://new.example/",
		Category: "other",
	}, {
		Name:      "allowlist",
		URL:       "https://new.example/",
		Whitelist: true,
		Category:  CategorySecurity,
	}} {
		t.Run(req.Name, func(t *testing.T) {
			data, err := json.Marshal(req)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPost, "http://example.org", bytes.NewReader(data))
			w := httptest.NewRecorder()
			d.handleFilteringAddURL(w, r)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Len(t, d.conf.Filters, 4)
		})
	}
}
