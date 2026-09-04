const paths = {
  arrow: 'M5 12h14m-6-6 6 6-6 6',
  upload: 'M12 16V4m-4 4 4-4 4 4M4 15v5h16v-5',
  check: 'm5 12 4 4L19 6',
  device: 'M4 4h16v12H4zM8 20h8m-4-4v4',
  report: 'M6 3h8l4 4v14H6zM14 3v5h4M9 12h6m-6 4h6',
  refresh: 'M20 10a8 8 0 0 0-14-4L3 9m0-5v5h5M4 14a8 8 0 0 0 14 4l3-3m0 5v-5h-5',
  shield: 'M12 3 4 6v6c0 4 4 7 8 9 4-2 8-5 8-9V6z',
}

export default function WorkspaceIcon({ name, size = 18 }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name] || paths.arrow} /></svg>
}
