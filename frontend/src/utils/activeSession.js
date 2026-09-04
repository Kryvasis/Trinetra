export const SESSION_KEY = 'cortex.active-session.v1'
export const SESSION_EVENT = 'cortex:active-session'
export const IDLE_TIMEOUT = 30 * 60 * 1000
export const validSession = name => typeof name === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(name)

export function decodeSession(raw, now = Date.now()) {
  try {
    const value = JSON.parse(raw)
    if (!validSession(value?.name) || !Number.isFinite(value.lastActivity)) return null
    return { ...value, expired: now - value.lastActivity >= IDLE_TIMEOUT || value.lastActivity > now }
  } catch { return null }
}

export function readSession() {
  try { return decodeSession(window.sessionStorage.getItem(SESSION_KEY)) } catch { return null }
}

export function writeSession(name, lastActivity = Date.now()) {
  if (!validSession(name)) return
  try { window.sessionStorage.setItem(SESSION_KEY, JSON.stringify({ name, lastActivity })) } catch { /* In-memory navigation still works. */ }
}

export function rememberSession(name) {
  if (!validSession(name)) return
  writeSession(name)
  window.dispatchEvent(new CustomEvent(SESSION_EVENT, { detail: name }))
}

export function sessionSearch(search, name) {
  const params = new URLSearchParams(search)
  if (validSession(name)) params.set('session', name)
  else params.delete('session')
  return params.size ? `?${params}` : ''
}
