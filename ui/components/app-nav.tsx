'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';
import { getSession } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { APP_SECTIONS, activeRoute, type AppRoute } from '@/lib/routes';
import { TONES } from '@/components/ui';

const MOBILE_NAV_ID = 'mobile-navigation';

const LINK_IDLE = `${TONES.navInactive} hover:bg-sky-200 hover:text-gray-900`;

function PageLinks({
  routes,
  current,
  className,
}: {
  routes: readonly AppRoute[];
  current: AppRoute | undefined;
  className: (active: boolean) => string;
}) {
  return (
    <>
      {routes.map((route) => (
        <Link
          key={route.href}
          href={route.href}
          aria-current={route === current ? 'page' : undefined}
          className={className(route === current)}
        >
          {route.label}
        </Link>
      ))}
    </>
  );
}

// The signed-in identity comes from the API's /session, which verifies the
// Cloudflare Access JWT; request headers are not trusted for it.
export function AppNav() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const session = useRequest((signal) => getSession({ signal }), []);
  const email = session.status === 'success' ? (session.data.email ?? undefined) : undefined;
  const role = session.status === 'success' ? (session.data.role ?? undefined) : undefined;
  const current = activeRoute(pathname);
  const section = APP_SECTIONS.find((entry) => current && entry.routes.includes(current));

  // A route change means the reader picked a destination; close the panel.
  useEffect(() => setOpen(false), [pathname]);

  return (
    <header className="border-b border-sky-200 bg-sky-100">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-6 px-4 py-3 sm:px-6 lg:px-8">
        <Link href="/issues" className="flex shrink-0 items-center gap-3">
          <img
            src="/khalifa-logo.png"
            alt=""
            width={40}
            height={40}
            className="h-10 w-10 rounded-lg"
          />
          <span className="text-lg font-semibold tracking-tight text-gray-900">Khalifa</span>
        </Link>

        <nav aria-label="Primary" className="hidden md:flex md:flex-1 md:gap-1">
          {APP_SECTIONS.map((entry) => (
            <Link
              key={entry.label}
              href={entry.routes[0].href}
              aria-current={entry === section ? 'true' : undefined}
              className={`rounded-md px-3 py-1.5 text-sm font-medium ${
                entry === section ? TONES.navActive : LINK_IDLE
              }`}
            >
              {entry.label}
            </Link>
          ))}
        </nav>

        <div className="flex items-center gap-3">
          {email && (
            <p className="hidden truncate text-sm text-gray-600 sm:block" title={role}>
              {email}
            </p>
          )}
          <button
            type="button"
            className="inline-flex items-center justify-center rounded-md p-2 text-gray-700 hover:bg-sky-200 hover:text-gray-900 md:hidden"
            aria-expanded={open}
            aria-controls={MOBILE_NAV_ID}
            onClick={() => setOpen((value) => !value)}
          >
            <span className="sr-only">{open ? 'Close menu' : 'Open menu'}</span>
            <svg
              className="h-6 w-6"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              aria-hidden="true"
            >
              {open ? (
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              ) : (
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 6h16M4 12h16M4 18h16"
                />
              )}
            </svg>
          </button>
        </div>
      </div>

      {section && (
        <nav
          aria-label={section.label}
          className="hidden border-t border-sky-200 bg-sky-50 md:block"
        >
          <div className="mx-auto flex max-w-7xl gap-1 overflow-x-auto px-4 sm:px-6 lg:px-8">
            <PageLinks
              routes={section.routes}
              current={current}
              className={(active) =>
                `whitespace-nowrap border-b-2 px-3 py-2.5 text-sm ${
                  active
                    ? 'border-gray-900 font-semibold text-gray-900'
                    : 'border-transparent text-gray-600 hover:text-gray-900'
                }`
              }
            />
          </div>
        </nav>
      )}

      {open && (
        <nav
          id={MOBILE_NAV_ID}
          aria-label="Primary"
          className="flex flex-col gap-3 border-t border-sky-200 px-4 py-3 md:hidden"
        >
          {APP_SECTIONS.map((entry) => (
            <div key={entry.label} className="flex flex-col gap-1">
              <p className="px-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
                {entry.label}
              </p>
              <PageLinks
                routes={entry.routes}
                current={current}
                className={(active) =>
                  `block rounded-md px-3 py-2 text-sm font-medium ${active ? TONES.navActive : LINK_IDLE}`
                }
              />
            </div>
          ))}
          {email && <p className="truncate px-3 text-sm text-gray-600">{email}</p>}
        </nav>
      )}
    </header>
  );
}
