/** True when a query has failed and has nothing to show. A failed background
 * refetch keeps the previous data, and a populated list must stay on screen
 * rather than be replaced by the error state. */
export function failedWithoutData<Q extends { isError: boolean; data: unknown }>(q: Q): q is Q & { isError: true; data: undefined } {
  return q.isError && q.data === undefined;
}
