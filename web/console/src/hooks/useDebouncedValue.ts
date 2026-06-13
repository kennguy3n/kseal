import { useEffect, useState } from "react";

// Returns a debounced copy of `value` that only updates after `delayMs` of
// quiescence. Used to coalesce per-keystroke filter typing into a single query
// so list endpoints aren't hit on every character (matters at 5000-tenant
// scale). The trailing edge always fires, so the final value is never dropped.
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(id);
  }, [value, delayMs]);

  return debounced;
}
