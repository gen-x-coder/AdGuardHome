/**
 * Filter update data
 */
export interface FilterSetUrlData {
    enabled: boolean;
    category?: 'default' | 'security' | 'parental';
    name: string;
    url: string;
}
