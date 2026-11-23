import type { FilterCategory } from './filterCategory';

/**
 * Filter subscription info
 */
export interface Filter {
    enabled: boolean;
    category?: FilterCategory;
    id: number;
    last_updated?: string;
    name: string;
    rules_count: number;
    url: string;
}
