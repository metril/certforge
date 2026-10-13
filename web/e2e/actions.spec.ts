import { expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { snap } from './screens';

// Actions are a reusable library. Attaching them to a grant needs an enrolled
// agent (exec) or a server target (wait), so the grant side is covered by the
// Go integration tests; this spec covers the library itself.
test('actions: create a wait and an exec action, group them, delete', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.goto(`/o/${E2E.orgSlug}/delivery/actions`);
  const actions = page.getByRole('table', { name: 'Actions' });

  // A server-run Wait action.
  await page.getByRole('button', { name: 'New action' }).click();
  const wait = page.getByRole('dialog', { name: 'New action' });
  await wait.getByLabel('Name', { exact: true }).fill('e2e-settle');
  await wait.getByRole('combobox', { name: 'Kind' }).click();
  await page.getByRole('option', { name: /^Wait/ }).click();
  await wait.getByLabel('Seconds').fill('5');
  await wait.getByRole('button', { name: 'Save' }).click();
  await expect(wait).toBeHidden();
  await expect(actions.getByRole('row', { name: /^e2e-settle/ })).toContainText('Wait');

  // An agent-run exec action.
  await page.getByRole('button', { name: 'New action' }).click();
  const exec = page.getByRole('dialog', { name: 'New action' });
  await exec.getByLabel('Name', { exact: true }).fill('e2e-true');
  await exec.getByLabel('Executable').fill('/bin/true');
  await exec.getByRole('button', { name: 'Save' }).click();
  await expect(exec).toBeHidden();
  await expect(actions.getByRole('row', { name: /^e2e-true/ })).toBeVisible();
  await snap(page, 'actions');

  // A group of both, in order.
  await page.getByRole('tab', { name: 'Groups' }).click();
  await page.getByRole('button', { name: 'New action group' }).click();
  const group = page.getByRole('dialog', { name: 'New action group' });
  await group.getByLabel('Name', { exact: true }).fill('e2e-group');
  for (const name of ['e2e-true', 'e2e-settle']) {
    await group.getByRole('combobox', { name: 'Add action' }).click();
    await page.getByRole('option', { name: new RegExp(`^${name}`) }).click();
  }
  await group.getByRole('button', { name: 'Save' }).click();
  await expect(group).toBeHidden();
  const groups = page.getByRole('table', { name: 'Action groups' });
  const groupRow = groups.getByRole('row', { name: /^e2e-group/ });
  await expect(groupRow).toContainText('2 actions');
  await expect(groupRow).toContainText('e2e-true → e2e-settle');
  await snap(page, 'action-groups');

  // Clean up: group first, then the actions.
  await groupRow.getByRole('button', { name: 'Delete e2e-group' }).click();
  const confirmGroup = page.getByRole('dialog', { name: 'Delete action group' });
  await confirmGroup.getByLabel('e2e-group').fill('e2e-group');
  await confirmGroup.getByRole('button', { name: 'Delete' }).click();
  await expect(confirmGroup).toBeHidden();
  await expect(groupRow).toHaveCount(0);

  await page.getByRole('tab', { name: 'Actions' }).click();
  for (const name of ['e2e-true', 'e2e-settle']) {
    await actions.getByRole('row', { name: new RegExp(`^${name}`) }).getByRole('button', { name: `Delete ${name}` }).click();
    const confirm = page.getByRole('dialog', { name: 'Delete action' });
    await confirm.getByLabel(name).fill(name);
    await confirm.getByRole('button', { name: 'Delete' }).click();
    await expect(confirm).toBeHidden();
    await expect(actions.getByRole('row', { name: new RegExp(`^${name}`) })).toHaveCount(0);
  }
});
