import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { POLL } from '@/lib/polling';
import { api, call } from '../client';

export const usersQuery = queryOptions({
  queryKey: ['users'],
  queryFn: async () => (await call(api.GET('/users'))).items,
  refetchInterval: POLL.list,
});

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, disabled }: { id: string; disabled: boolean }) =>
      call(api.PATCH('/users/{id}', { params: { path: { id } }, body: { disabled } })),
    // Disabling goes through ConfirmDestructive, which shows its own inline
    // error on a 409 (self-disable or last admin); re-enabling shows a toast
    // from the row itself (see UsersTab), so this stays silent either way.
    meta: { silent: true, success: 'User updated' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  });
}
