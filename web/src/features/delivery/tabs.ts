// Own tiny module (like certificates/detail/tabs.ts): the route's beforeLoad needs it without pulling in the detail page.
export const TARGET_TABS = ['overview', 'grants', 'runs'] as const;
export type TargetTab = (typeof TARGET_TABS)[number];
