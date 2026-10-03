import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { renderUI } from '@/test/render';
import { help, type Help, type HelpKey } from '@/lib/help';
import { HelpTip } from './HelpTip';

const entries = Object.entries(help) as [HelpKey, Help][];
const withLink = entries.find(([, h]) => h.learnMore)![0];
const plain = entries.find(([, h]) => !h.learnMore)![0];

it('opens a keyboard-reachable popover with a Learn more link for entries that have one', async () => {
  const { user } = renderUI(<HelpTip id={withLink} label="Thing" />);
  await user.tab();
  expect(screen.getByRole('button', { name: 'Help: Thing' })).toHaveFocus();
  await user.keyboard('{Enter}');
  const link = await screen.findByRole('link', { name: 'Learn more' });
  await user.tab();
  expect(link).toHaveFocus();
});

it('keeps a plain tip as a tooltip labelled Help', async () => {
  const { user } = renderUI(<HelpTip id={plain} />);
  await user.hover(screen.getByRole('button', { name: 'Help' }));
  expect((await screen.findAllByText((help[plain] as Help).text)).length).toBeGreaterThan(0);
});
