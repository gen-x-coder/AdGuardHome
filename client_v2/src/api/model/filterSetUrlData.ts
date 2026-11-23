import type { FilterCategory } from './filterCategory';

/**
 * Filter update data
 */
export interface FilterSetUrlData {
    category?: FilterCategory;
    enabled: boolean;
    name: string;
    url: string;
}
