import type { FilterCategory } from './filterCategory';

/**
 * /add_url request data
 */
export interface AddUrlRequest {
    category?: FilterCategory;
    name?: string;
    /** URL or an absolute path to the file containing filtering rules. */
    url?: string;
    whitelist?: boolean;
}
