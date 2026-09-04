export default function SceneHeader({ title, description }) {
  return (
    <header className="workspace-header">
      <h1 className="page-title">{title}</h1>
      <p className="page-description">{description}</p>
    </header>
  )
}
