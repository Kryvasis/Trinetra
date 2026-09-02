export default function Spinner({ size = 18, style }) {
  return <span className="spinner" role="status" aria-label="Loading" style={{ width: size, height: size, ...style }} />
}
