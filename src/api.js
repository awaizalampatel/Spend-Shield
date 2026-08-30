/**
 * The only place that talks to the backend.
 *
 * The token lives in localStorage rather than a cookie because the API is
 * bearer-authenticated and stateless — there is no cookie for a CSRF to ride on.
 * A 401 clears it and bounces to the login screen from wherever you were.
 */
const TOKEN_KEY = 'spendshield.token';
const USER_KEY = 'spendshield.user';

export const tokenStore = {
  get: () => {
    try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
  },
  set: (t, user) => {
    try {
      localStorage.setItem(TOKEN_KEY, t);
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    } catch { /* private window — the session just won't survive a reload */ }
  },
  user: () => {
    try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null'); } catch { return null; }
  },
  clear: () => {
    try { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY); } catch { /* ignore */ }
  },
};

/** Raised on a non-2xx response so callers can show the server's own message. */
export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

let onUnauthorized = () => {};
export const setUnauthorizedHandler = (fn) => { onUnauthorized = fn; };

export async function api(path, { method = 'GET', body, signal } = {}) {
  const token = tokenStore.get();
  const res = await fetch(`/api/v1/${path}`, {
    method,
    signal,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  let data = null;
  try { data = await res.json(); } catch { /* an empty or non-JSON body */ }

  if (res.status === 401) {
    tokenStore.clear();
    onUnauthorized();
    throw new ApiError(401, data?.error || 'Your session has expired.');
  }
  if (!res.ok) {
    throw new ApiError(res.status, data?.error || `Request failed (${res.status}).`);
  }
  return data;
}

export const login = async (email, password) => {
  const res = await api('login.php', { method: 'POST', body: { email, password } });
  tokenStore.set(res.token, res.user);
  return res.user;
};

export const logout = async () => {
  try { await api('login.php?logout=1', { method: 'POST' }); } catch { /* leaving anyway */ }
  tokenStore.clear();
};

/** Money arrives from the API as {value, display}. Never reformat it here — the
 *  server decides how a rupee figure reads, so every surface agrees. */
export const rupees = (m) => (m && typeof m === 'object' ? m.display : '—');
export const amount = (m) => (m && typeof m === 'object' ? m.value : 0);
