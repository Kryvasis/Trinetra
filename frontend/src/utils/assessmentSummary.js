export const count = value => Number.isFinite(value) && value >= 0 ? value : 0

export function summarizeDevices(devices) {
  return devices.reduce((totals, device) => {
    const passed = count(device.pass_count)
    const failed = count(device.fail_count)
    const total = Math.max(count(device.total_checks), passed + failed)
    return { passed: totals.passed + passed, failed: totals.failed + failed, unresolved: totals.unresolved + total - passed - failed, total: totals.total + total }
  }, { passed: 0, failed: 0, unresolved: 0, total: 0 })
}
