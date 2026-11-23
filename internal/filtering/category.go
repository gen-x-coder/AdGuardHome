package filtering

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// FilterCategory is the reporting category of a blocklist.  It only affects
// statistics and never changes filtering decisions or DNS responses.
type FilterCategory string

// Valid FilterCategory values.
const (
	// CategoryDefault is the category of lists without an explicit category.
	CategoryDefault FilterCategory = "default"

	// CategorySecurity attributes blocks to the safe browsing statistics.
	CategorySecurity FilterCategory = "security"

	// CategoryParental attributes blocks to the parental control statistics.
	CategoryParental FilterCategory = "parental"
)

// Effective returns c or, if c is empty, [CategoryDefault].  An empty category
// comes from configurations and API clients that predate categories.
func (c FilterCategory) Effective() (eff FilterCategory) {
	if c == "" {
		return CategoryDefault
	}

	return c
}

// validateFilterCategory returns an error if c isn't a valid category for a
// blocklist or, if isAllowlist is true, for an allowlist.
func validateFilterCategory(c FilterCategory, isAllowlist bool) (err error) {
	switch c.Effective() {
	case CategoryDefault, CategorySecurity, CategoryParental:
		// Go on.
	default:
		return fmt.Errorf("unknown filter category %q", c)
	}

	if isAllowlist && c.Effective() != CategoryDefault {
		return fmt.Errorf("allowlists cannot be categorized as %q", c)
	}

	return nil
}

// resetInvalidCategories resets the invalid categories in lists, for example
// ones edited by hand in the configuration file, and logs a warning for each.
func (d *DNSFilter) resetInvalidCategories(
	ctx context.Context,
	lists []FilterYAML,
	isAllowlist bool,
) {
	for i := range lists {
		flt := &lists[i]
		err := validateFilterCategory(flt.Category, isAllowlist)
		if err != nil {
			d.logger.WarnContext(ctx, "resetting filter category", "id", flt.ID, slogutil.KeyError, err)
			flt.Category = ""
		}
	}
}

// reportingCategories maps the IDs of the blocklists with a non-default
// category to that category.
type reportingCategories map[rulelist.APIID]FilterCategory

// updateReportingCategoriesLocked replaces the categories used by
// [DNSFilter.ReportingCategory] with the ones from d.conf.Filters.
// d.conf.filtersMu must be locked, unless d is not used concurrently yet.
func (d *DNSFilter) updateReportingCategoriesLocked() {
	cats := reportingCategories{}
	for _, flt := range d.conf.Filters {
		c := flt.Category.Effective()
		if c != CategoryDefault {
			// #nosec G115 -- The overflow is required for backwards compatibility.
			cats[rulelist.APIID(flt.ID)] = c
		}
	}

	if len(cats) == 0 {
		d.reportingCats.Store(nil)

		return
	}

	d.reportingCats.Store(&cats)
}

// ReportingCategory returns the reporting category of res.  Only results with
// [FilteredBlockList] can have a category other than [CategoryDefault].  If
// the applied rules come from several lists, [CategorySecurity] takes
// precedence over [CategoryParental].  It is safe for concurrent use and does
// not lock d.conf.filtersMu, which can be held during list downloads.
func (d *DNSFilter) ReportingCategory(res *Result) (c FilterCategory) {
	c = CategoryDefault

	cats := d.reportingCats.Load()
	if cats == nil || res == nil || res.Reason != FilteredBlockList {
		return c
	}

	for _, r := range res.Rules {
		switch (*cats)[r.FilterListID] {
		case CategorySecurity:
			return CategorySecurity
		case CategoryParental:
			c = CategoryParental
		default:
			// Go on.
		}
	}

	return c
}
