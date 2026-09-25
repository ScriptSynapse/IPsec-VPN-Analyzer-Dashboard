import { useCallback, useEffect, useState } from "react";

/** Runs an async function, tracking {data, error, loading}, re-running whenever deps change. */
export function useAsync(fn, deps) {
  const [state, setState] = useState({ data: null, error: null, loading: true });

  const reload = useCallback(() => {
    let cancelled = false;
    // Clear stale data immediately, not just on deps changing -- a consumer
    // whose deps changed (e.g. a report type toggle) must never render the
    // previous, differently-shaped result while the new one is in flight.
    setState({ data: null, error: null, loading: true });
    fn()
      .then((data) => {
        if (!cancelled) setState({ data, error: null, loading: false });
      })
      .catch((error) => {
        if (!cancelled) setState({ data: null, error, loading: false });
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => reload(), [reload]);

  return { ...state, reload };
}
