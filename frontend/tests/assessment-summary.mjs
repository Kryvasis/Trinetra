import assert from 'node:assert/strict'
import { summarizeDevices } from '../src/utils/assessmentSummary.js'

assert.deepEqual(summarizeDevices([]), { passed: 0, failed: 0, unresolved: 0, total: 0 })
assert.deepEqual(summarizeDevices([{ pass_count: 12, fail_count: 2, total_checks: 20 }, { pass_count: 3, fail_count: 1, total_checks: 4 }]), { passed: 15, failed: 3, unresolved: 6, total: 24 })
assert.deepEqual(summarizeDevices([{ pass_count: 5, fail_count: 2, total_checks: 1 }]), { passed: 5, failed: 2, unresolved: 0, total: 7 })
assert.deepEqual(summarizeDevices([{ pass_count: -1, fail_count: '2', total_checks: NaN }]), { passed: 0, failed: 0, unresolved: 0, total: 0 })
assert.deepEqual(summarizeDevices([{ total_checks: 8 }]), { passed: 0, failed: 0, unresolved: 8, total: 8 })
assert.deepEqual(summarizeDevices([{ pass_count: 8, total_checks: 8 }]), { passed: 8, failed: 0, unresolved: 0, total: 8 })
