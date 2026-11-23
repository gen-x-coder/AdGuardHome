import cn from 'clsx';
import { createMemo } from 'solid-js';

import intl from 'panel/common/intl';
import { Input } from 'panel/common/controls/Input';
import { Select } from 'panel/common/controls/Select';
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

export const ManualFilterForm = (props: Props) => {
    const categoryOptions = createMemo(() => [
        { value: 'default', label: intl.getMessage('blocklist_category_default') },
        { value: 'security', label: intl.getMessage('blocklist_category_security') },
        { value: 'parental', label: intl.getMessage('blocklist_category_parental') },
    ]);

    return (
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
                <label for="filters_category_input">
                    {intl.getMessage('blocklist_stats_category')}
                </label>
                <Select
                    id="filters_category"
                    inputId="filters_category_input"
                    options={categoryOptions()}
                    value={categoryOptions().find((option) => option.value === props.category)}
                    onChange={(option) => props.onCategoryChange(option.value as Props['category'])}
                    optionTestIdPrefix="blocklist-category"
                    size="responsive"
                    height="medium"
                    isSearchable={false}
                    onCard
                />
            </div>
        </div>
    );
};
