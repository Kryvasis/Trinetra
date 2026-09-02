export default function SceneHeader({ label, title, description }) {
  return (
    <header className="workspace-header">
      <span className="workspace-kicker">{label}</span>
      <h1 className="page-title">{title}</h1>
      <p className="page-description">{description}</p>
    </header>
  )
}

