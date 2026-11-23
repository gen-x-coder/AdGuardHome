import cn from 'clsx';

import intl from 'panel/common/intl';
import { Input } from 'panel/common/controls/Input';
import theme from 'panel/lib/theme';

type Props = {
    class?: string;
    name: string;
    url: string;
    category: 'default' | 'security' | 'parental';
    onCategoryChange: (value: 'default' | 'security' | 'parental') => void;
    nameError?: string;
    urlError?: string;
    onNameChange: (value: string) => void;
    onUrlChange: (value: string) => void;
    onNameBlur?: () => void;
    onUrlBlur?: () => void;
};

export const ManualFilterForm = (props: Props) => (
    <div class={cn(theme.form.group, props.class)}>
        <div class={theme.form.input}>
            <Input
                type="text"
                id="filters_name"
                label={intl.getMessage('name_label')}
                placeholder={intl.getMessage('blocklist_placeholder_example')}
                value={props.name}
                onChange={(e) => props.onNameChange((e.target as HTMLInputElement).value)}
                onBlur={() => props.onNameBlur?.()}
                errorMessage={props.nameError}
                size="large"
                onCard
            />
        </div>

        <div class={theme.form.input}>
            <Input
                type="text"
                id="filters_url"
                label={intl.getMessage('blocklist_url_file_path')}
                placeholder={intl.getMessage('blocklist_url_file_path')}
                value={props.url}
                onChange={(e) => props.onUrlChange((e.target as HTMLInputElement).value)}
                onBlur={() => props.onUrlBlur?.()}
                errorMessage={props.urlError}
                size="large"
                onCard
            />
        </div>
        <div class={theme.form.input}>
            <label for="filters_category">Category</label>
            <select
                id="filters_category"
                value={props.category}
                onChange={(e) => props.onCategoryChange(e.currentTarget.value as 'default' | 'security' | 'parental')}
                style={{ width: '100%', padding: '0.75rem' }}
            >
                <option value="default">Default — blocked by filters</option>
                <option value="security">Security — blocked threats</option>
                <option value="parental">Parental — blocked adult websites</option>
            </select>
        </div>
    </div>
);
