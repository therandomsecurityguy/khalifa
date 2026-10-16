export interface AppRoute {
  href: string;
  label: string;
  // Other top-level paths that belong to this page, such as Identity's tools.
  includes?: readonly string[];
}

// The top bar shows the sections; the row beneath lists the current section's pages.
export const APP_SECTIONS: ReadonlyArray<{ label: string; routes: readonly AppRoute[] }> = [
  { label: 'Boards', routes: [{ href: '/trends', label: 'Trends' }] },
  {
    label: 'Risks',
    routes: [
      { href: '/issues', label: 'Issues' },
      { href: '/compliance', label: 'Compliance' },
    ],
  },
  {
    label: 'Inventory',
    routes: [
      { href: '/resources', label: 'Resources' },
      { href: '/attack-paths', label: 'Attack paths' },
      { href: '/identity', label: 'Identity', includes: ['/least-privilege'] },
    ],
  },
  {
    label: 'Connectors',
    routes: [
      { href: '/data-sources', label: 'Data sources' },
      { href: '/integrations', label: 'Integrations' },
    ],
  },
];

export const APP_ROUTES: readonly AppRoute[] = APP_SECTIONS.flatMap((section) => section.routes);

const within = (pathname: string, href: string) =>
  pathname === href || pathname.startsWith(`${href}/`);

export function activeRoute(pathname: string): AppRoute | undefined {
  return APP_ROUTES.find((route) =>
    [route.href, ...(route.includes ?? [])].some((href) => within(pathname, href))
  );
}

export const IDENTITY_ROUTES = [
  {
    href: '/identity/effective-permissions',
    label: 'Effective permissions',
    description: 'Resolved allow, deny, and conditional grants for a principal.',
  },
  {
    href: '/identity/escalation-paths',
    label: 'Escalation paths',
    description: 'Privilege-escalation and lateral-movement paths.',
  },
  {
    href: '/identity/unused-permissions',
    label: 'Unused permissions',
    description: 'Used versus unused actions from CloudTrail usage.',
  },
  {
    href: '/identity/rightsizing',
    label: 'Rightsizing',
    description: 'On-demand least-privilege recommendation for one principal.',
  },
  {
    href: '/identity/trust-graph',
    label: 'Trust graph',
    description: 'IAM TRUSTS edges, bounded and pageable.',
  },
  {
    href: '/least-privilege',
    label: 'Least privilege',
    description: 'Sweep findings across accounts.',
  },
] as const;

export function resourceHref(arn: string): string {
  return `/resources?arn=${encodeURIComponent(arn)}`;
}

export function principalHref(path: string, principal: string): string {
  return `${path}?principal=${encodeURIComponent(principal)}`;
}
