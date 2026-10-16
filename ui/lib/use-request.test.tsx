import { act, renderHook, waitFor } from '@testing-library/react';
import { useAsyncAction, useRequest } from './use-request';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('useRequest', () => {
  it('settles with the loaded data', async () => {
    const { result } = renderHook(() => useRequest(async () => 'ok', []));
    expect(result.current.status).toBe('loading');
    await waitFor(() => expect(result.current.status).toBe('success'));
    expect(result.current.data).toBe('ok');
  });

  it('ignores a late response from a superseded request', async () => {
    const first = deferred<string>();
    const second = deferred<string>();
    const responses = [first, second];
    const load = jest.fn(() => responses.shift()!.promise);
    const { result, rerender } = renderHook(({ filter }) => useRequest(load, [filter]), {
      initialProps: { filter: 'open' },
    });

    rerender({ filter: 'resolved' });
    expect(load).toHaveBeenCalledTimes(2);

    await act(async () => second.resolve('resolved issues'));
    await act(async () => first.resolve('open issues'));

    expect(result.current.status).toBe('success');
    expect(result.current.data).toBe('resolved issues');
  });

  it('aborts the in-flight request when inputs change or the component unmounts', () => {
    const signals: AbortSignal[] = [];
    const load = jest.fn((signal: AbortSignal) => {
      signals.push(signal);
      return new Promise<string>(() => undefined);
    });
    const { rerender, unmount } = renderHook(({ id }) => useRequest(load, [id]), {
      initialProps: { id: 1 },
    });
    rerender({ id: 2 });
    expect(signals[0].aborted).toBe(true);
    expect(signals[1].aborted).toBe(false);
    unmount();
    expect(signals[1].aborted).toBe(true);
  });

  it('reports failures and reloads on demand', async () => {
    const load = jest
      .fn<Promise<string>, [AbortSignal]>()
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce('recovered');
    const { result } = renderHook(() => useRequest(load, []));
    await waitFor(() => expect(result.current.status).toBe('error'));
    expect((result.current.error as Error).message).toBe('boom');

    act(() => result.current.reload());
    await waitFor(() => expect(result.current.status).toBe('success'));
    expect(result.current.data).toBe('recovered');
  });

  it('stays idle and never loads while disabled', () => {
    const load = jest.fn(async () => 'never');
    const { result } = renderHook(() => useRequest(load, [], { enabled: false }));
    expect(result.current.status).toBe('idle');
    expect(load).not.toHaveBeenCalled();
  });
});

describe('useAsyncAction', () => {
  it('tracks pending state and reports success', async () => {
    const gate = deferred<void>();
    const { result } = renderHook(() => useAsyncAction(() => gate.promise));
    let outcome: Promise<boolean> | undefined;
    act(() => {
      outcome = result.current.run();
    });
    expect(result.current.pending).toBe(true);
    await act(async () => gate.resolve());
    expect(result.current.pending).toBe(false);
    await expect(outcome).resolves.toBe(true);
  });

  it('captures the failure so the caller can show it', async () => {
    const { result } = renderHook(() =>
      useAsyncAction(async () => {
        throw new Error('rejected');
      })
    );
    let outcome = true;
    await act(async () => {
      outcome = await result.current.run();
    });
    expect(outcome).toBe(false);
    expect((result.current.error as Error).message).toBe('rejected');
    act(() => result.current.clearError());
    expect(result.current.error).toBeUndefined();
  });
});
