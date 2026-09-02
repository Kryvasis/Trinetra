export default function Toast({ toasts }) {
  if (!toasts.length) return null
  return (
    <div className="toast-container" aria-live="polite" aria-atomic="false">
      {toasts.map(t => (
        <div key={t.id} className={`toast toast-${t.type}`} role={t.type === 'error' ? 'alert' : 'status'}>
          <span>{t.msg}</span>
        </div>
      ))}
    </div>
  )
}
