import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { help } from '@/lib/help';
import { renderUI } from '@/test/render';
import { DataTable } from './DataTable';
import { HintLabel } from './HintLabel';
import { PrimaryCell } from './PrimaryCell';

it('HintLabel shows the help copy as a tooltip on keyboard focus, with no help icon', async () => {
  const { user } = renderUI(<HintLabel id="target.usedBy">Used by</HintLabel>);
  expect(screen.queryByRole('button', { name: 'Help' })).not.toBeInTheDocument();
  await user.tab();
  expect(screen.getByText('Used by')).toHaveFocus();
  expect(await screen.findByRole('tooltip')).toHaveTextContent(help['target.usedBy'].text);
});

it('PrimaryCell tooltips metaTitle instead of the meta line when given', async () => {
  const { user } = renderUI(<PrimaryCell primary="pem" meta={['a.pem']} metaTitle="/etc/ssl/a.pem" />);
  await user.hover(screen.getByText('a.pem'));
  expect(await screen.findByRole('tooltip')).toHaveTextContent('/etc/ssl/a.pem');
});

it('DataTable column hint tooltips the sortable header label', async () => {
  const { user } = renderUI(
    <DataTable
      data={[{ id: '1' }]}
      getRowId={(r) => r.id}
      ariaLabel="t"
      sort="nextRenewAt"
      onSort={() => {}}
      columns={[{ id: 'n', header: 'Next renewal', meta: { sortKey: 'nextRenewAt', hint: 'cert.nextRenew' }, cell: () => 'x' }]}
    />,
  );
  await user.hover(screen.getByText('Next renewal'));
  expect(await screen.findByRole('tooltip')).toHaveTextContent(help['cert.nextRenew'].text);
});
