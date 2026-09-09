export const ACTIVITY_EVENT = 'cortex:activity-stream'

export function createOperationId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID()
  return `op-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
}

export function announceActivity(detail) {
  window.dispatchEvent(new CustomEvent(ACTIVITY_EVENT, { detail }))
}
