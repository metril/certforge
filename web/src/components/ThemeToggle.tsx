import { Monitor, Moon, Sun } from 'lucide-react';
import { SegmentedControl } from './SegmentedControl';
import { useTheme, type ThemePref } from '@/lib/theme';

export function ThemeToggle() {
  const { pref, setPref } = useTheme();
  return (
    <SegmentedControl<ThemePref>
      aria-label="Theme"
      size="sm"
      value={pref}
      onChange={setPref}
      options={[
        { value: 'system', label: <><Monitor className="size-3.5" aria-hidden />System</> },
        { value: 'light', label: <><Sun className="size-3.5" aria-hidden />Light</> },
        { value: 'dark', label: <><Moon className="size-3.5" aria-hidden />Dark</> },
      ]}
    />
  );
}
