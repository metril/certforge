import { useRouteContext } from '@tanstack/react-router';
import type { Me, Org } from '@/api/types';

export function useOrg(): Org {
  return useRouteContext({ from: '/_app/o/$org', select: (c) => c.org });
}

export function useMe(): Me {
  return useRouteContext({ from: '/_app', select: (c) => c.me });
}
