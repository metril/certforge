import '@tanstack/react-router';

declare module '@tanstack/react-router' {
  interface StaticDataRouteOption {
    /** The page renders its own header + breadcrumb, so the section layout (e.g. Delivery) drops its header. */
    ownHeader?: boolean;
  }
}
