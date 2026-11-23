/**
 * Filter subscription info
 */
export interface Filter {
    enabled: boolean;
    category?: 'default' | 'security' | 'parental';
    id: number;
    last_updated?: string;
    name: string;
    rules_count: number;
    url: string;
}
