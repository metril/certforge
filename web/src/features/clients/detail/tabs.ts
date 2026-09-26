// Own module (like certificates/detail/tabs.ts): the route's beforeLoad
// needs the list without pulling the detail components into the eager chunk.
export const CLIENT_TABS = ['certificates', 'settings'] as const;
export type ClientTab = (typeof CLIENT_TABS)[number];
export const DEFAULT_CLIENT_TAB: ClientTab = CLIENT_TABS[0];
export const CLIENT_TAB_LABEL: Record<ClientTab, string> = { certificates: 'Certificates', settings: 'Settings' };
