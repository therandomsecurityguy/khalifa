'use client';

import { useCallback, useEffect, useState, type DependencyList } from 'react';
import { isAbortError } from '@/lib/api';

export type RequestState<T> =
  | { status: 'idle'; data?: undefined; error?: undefined }
  | { status: 'loading'; data?: undefined; error?: undefined }
  | { status: 'success'; data: T; error?: undefined }
  | { status: 'error'; data?: undefined; error: unknown };

export type RequestResult<T> = RequestState<T> & { reload: () => void };

// Runs `load` whenever `deps` change and settles independently of any other
// request on the page. The previous request is aborted when deps change or the
// component unmounts, and a response from an aborted request never reaches
// state, so a slow answer for an old filter cannot overwrite the current one.
export function useRequest<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: DependencyList,
  { enabled = true }: { enabled?: boolean } = {}
): RequestResult<T> {
  const [state, setState] = useState<RequestState<T>>({ status: enabled ? 'loading' : 'idle' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!enabled) {
      setState({ status: 'idle' });
      return;
    }
    const controller = new AbortController();
    setState({ status: 'loading' });
    load(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setState({ status: 'success', data });
      },
      (error: unknown) => {
        if (!controller.signal.aborted && !isAbortError(error))
          setState({ status: 'error', error });
      }
    );
    return () => controller.abort();
  }, [...deps, attempt, enabled]);

  const reload = useCallback(() => setAttempt((value) => value + 1), []);

  return { ...state, reload };
}

export interface AsyncAction<Args extends unknown[]> {
  run: (...args: Args) => Promise<boolean>;
  pending: boolean;
  error: unknown;
  clearError: () => void;
}

// Wraps a user-triggered action (search, download, status change) with pending
// and failure state so every button can show progress and report what failed.
export function useAsyncAction<Args extends unknown[]>(
  action: (...args: Args) => Promise<void>
): AsyncAction<Args> {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(undefined);

  const run = useCallback(
    async (...args: Args) => {
      setPending(true);
      setError(undefined);
      try {
        await action(...args);
        return true;
      } catch (failure) {
        setError(failure);
        return false;
      } finally {
        setPending(false);
      }
    },
    [action]
  );

  const clearError = useCallback(() => setError(undefined), []);

  return { run, pending, error, clearError };
}
