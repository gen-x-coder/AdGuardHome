package filtering

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
)

// FilterCategory classifies *reports* about a blocked request.  It does not
// change DNS filtering, block responses, or the priority of filter rules.
type FilterCategory string

const (
	CategoryDefault  FilterCategory = "default"
	CategorySecurity FilterCategory = "security"
	CategoryParental FilterCategory = "parental"
)

// Effective returns the category used when the setting was omitted by an old
// configuration or API client.
func (c FilterCategory) Effective() FilterCategory {
	if c == "" {
		return CategoryDefault
	}

	return c
}

func validateFilterCategory(c FilterCategory, isAllowlist bool) error {
	switch c.Effective() {
	case CategoryDefault, CategorySecurity, CategoryParental:
	default:
		return fmt.Errorf("unknown filter category %q", c)
	}

	if isAllowlist && c.Effective() != CategoryDefault {
		return fmt.Errorf("allowlists cannot be categorized as %q", c)
	}

	return nil
}

// categoryForRules classifies only the ACTUALLY APPLIED filtering rules.
// Provisional precedence: security > parental > default.
func categoryForRules(applied []*ResultRule, categories map[rulelist.APIID]FilterCategory) FilterCategory {
	category := CategoryDefault
	for _, rule := range applied {
		if rule == nil {
			continue
		}
		switch categories[rule.FilterListID].Effective() {
		case CategorySecurity:
			return CategorySecurity
		case CategoryParental:
			category = CategoryParental
		}
	}
	return category
}

// reportingCategoryForLists classifies applied blocklist rules against the
// current list configuration.  Caller must hold the filters read lock.
// Security takes precedence over parental, which takes precedence over default.
// Avoid allocating a temporary map in the DNS request hot path.
func reportingCategoryForLists(applied []*ResultRule, lists []FilterYAML) FilterCategory {
	result := CategoryDefault
	for _, rule := range applied {
		if rule == nil {
			continue
		}
		for i := range lists {
			if rulelist.APIID(lists[i].ID) != rule.FilterListID {
				continue
			}
			switch lists[i].Category.Effective() {
			case CategorySecurity:
				return CategorySecurity
			case CategoryParental:
				result = CategoryParental
			}
			break
		}
	}
	return result
}

// ReportingCategory returns the reporting category of applied blocklist rules.
// It does not alter rule matching, blocking reasons, or DNS answers.
func (d *DNSFilter) ReportingCategory(result *Result) FilterCategory {
	if result == nil || result.Reason != FilteredBlockList || len(result.Rules) == 0 {
		return CategoryDefault
	}
	d.conf.filtersMu.RLock()
	defer d.conf.filtersMu.RUnlock()
	return reportingCategoryForLists(result.Rules, d.conf.Filters)
}
