export default function Spinner({ size = 18, style }) {
  return <span className="spinner" style={{ width: size, height: size, ...style }} />
}
