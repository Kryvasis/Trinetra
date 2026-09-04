import assert from 'node:assert/strict'
import { test } from 'node:test'
import { decodeSession, validSession, sessionSearch, IDLE_TIMEOUT } from '../src/utils/activeSession.js'

test('valid identifiers only', () => {
  assert.equal(validSession('demo-2026_01'), true)
  for (const name of ['', '../secret', 'a?session=b', 'x'.repeat(65), null]) assert.equal(validSession(name), false)
})
test('expiry boundary and clock rollback', () => {
  const raw = JSON.stringify({ name: 'demo', lastActivity: 1000 })
  assert.equal(decodeSession(raw, 1000 + IDLE_TIMEOUT - 1).expired, false)
  assert.equal(decodeSession(raw, 1000 + IDLE_TIMEOUT).expired, true)
  assert.equal(decodeSession(raw, 999).expired, true)
})
test('corrupt or malformed storage is ignored', () => {
  for (const raw of ['{', 'null', '{}', '{"name":"demo","lastActivity":"100"}']) assert.equal(decodeSession(raw), null)
})
test('navigation preserves source and filters while replacing the session', () => {
  assert.equal(sessionSearch('?source=website&session=old&frameworks=CIS', 'new'), '?source=website&session=new&frameworks=CIS')
  assert.equal(sessionSearch('?source=website&session=old', ''), '?source=website')
  assert.equal(sessionSearch('?session=old', ''), '')
})
