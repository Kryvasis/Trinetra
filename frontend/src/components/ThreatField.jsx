import { useEffect, useRef } from 'react'

const ROUTE_ROTATION = {
  '/': 0.25,
  '/results': 1.05,
  '/training': 1.85,
  '/devices': 2.65,
  '/dashboard': 3.45,
}

const SIGNALS = [
  { lat: 24, lon: -118, label: 'ACL' },
  { lat: 47, lon: 12, label: 'SSH' },
  { lat: -18, lon: 78, label: 'AAA' },
  { lat: 6, lon: 154, label: 'SYSLOG' },
  { lat: -42, lon: -36, label: 'SNMP' },
]

function toRadians(value) {
  return value * Math.PI / 180
}

export default function ThreatField({ scene = '/' }) {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return undefined

    const context = canvas.getContext('2d', { alpha: true })
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const pointer = { x: 0, y: 0 }
    const routeRotation = ROUTE_ROTATION[scene] ?? 0
    let width = 0
    let height = 0
    let dpr = 1
    let frame = 0
    let previousFrame = 0
    let visible = !document.hidden

    const resize = () => {
      width = document.documentElement.clientWidth
      height = window.innerHeight
      dpr = Math.min(window.devicePixelRatio || 1, 1.25)
      canvas.width = Math.round(width * dpr)
      canvas.height = Math.round(height * dpr)
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`
      context.setTransform(dpr, 0, 0, dpr, 0, 0)
    }

    const project = (latitude, longitude, rotation, centerX, centerY, radius) => {
      const phi = toRadians(latitude)
      const theta = toRadians(longitude) + rotation
      const x = Math.cos(phi) * Math.sin(theta)
      const y = Math.sin(phi)
      const z = Math.cos(phi) * Math.cos(theta)
      const tilt = -0.22
      const tiltedY = y * Math.cos(tilt) - z * Math.sin(tilt)
      const tiltedZ = y * Math.sin(tilt) + z * Math.cos(tilt)

      return {
        x: centerX + x * radius,
        y: centerY - tiltedY * radius,
        depth: tiltedZ,
      }
    }

    const drawMesh = (rotation, centerX, centerY, radius) => {
      context.lineWidth = 0.65

      const drawCurve = points => {
        for (let index = 1; index < points.length; index += 1) {
          const previous = points[index - 1]
          const current = points[index]
          const depth = Math.max(-1, Math.min(1, (previous.depth + current.depth) / 2))
          context.strokeStyle = `rgba(111, 158, 166, ${depth > 0 ? 0.28 + depth * 0.24 : 0.055})`
          context.beginPath()
          context.moveTo(previous.x, previous.y)
          context.lineTo(current.x, current.y)
          context.stroke()
        }
      }

      for (let latitude = -60; latitude <= 60; latitude += 20) {
        const points = []
        for (let longitude = -180; longitude <= 180; longitude += 6) {
          points.push(project(latitude, longitude, rotation, centerX, centerY, radius))
        }
        drawCurve(points)
      }

      for (let longitude = -150; longitude <= 180; longitude += 30) {
        const points = []
        for (let latitude = -88; latitude <= 88; latitude += 4) {
          points.push(project(latitude, longitude, rotation, centerX, centerY, radius))
        }
        drawCurve(points)
      }
    }

    const drawSignals = (rotation, centerX, centerY, radius) => {
      const visibleSignals = SIGNALS
        .map(signal => ({ ...signal, point: project(signal.lat, signal.lon, rotation, centerX, centerY, radius) }))
        .filter(signal => signal.point.depth > -0.05)

      visibleSignals.forEach((signal, index) => {
        const point = signal.point
        const outward = point.x >= centerX ? 1 : -1
        const reach = width < 640 ? 24 : 54 + index * 5
        const anchorX = point.x + outward * reach
        const anchorY = point.y + (index % 2 === 0 ? -22 : 26)
        const isException = signal.label === 'AAA'
        const color = isException ? '188, 102, 78' : '116, 165, 173'

        context.strokeStyle = `rgba(${color}, ${isException ? 0.58 : 0.35})`
        context.lineWidth = isException ? 1.1 : 0.7
        context.beginPath()
        context.moveTo(point.x, point.y)
        context.lineTo(anchorX, anchorY)
        context.lineTo(anchorX + outward * 18, anchorY)
        context.stroke()

        context.fillStyle = `rgba(${color}, ${isException ? 0.9 : 0.7})`
        context.beginPath()
        context.arc(point.x, point.y, isException ? 3.4 : 2.2, 0, Math.PI * 2)
        context.fill()

        if (width >= 720) {
          context.font = '10px "Cascadia Code", Consolas, monospace'
          context.textAlign = outward > 0 ? 'left' : 'right'
          context.fillStyle = 'rgba(220, 218, 224, 0.56)'
          context.fillText(signal.label, anchorX + outward * 23, anchorY + 3)
        }
      })

      for (let index = 1; index < visibleSignals.length; index += 1) {
        const previous = visibleSignals[index - 1].point
        const current = visibleSignals[index].point
        context.strokeStyle = index === 2 ? 'rgba(188, 102, 78, 0.34)' : 'rgba(116, 165, 173, 0.15)'
        context.lineWidth = index === 2 ? 1 : 0.6
        context.beginPath()
        context.moveTo(previous.x, previous.y)
        context.lineTo(current.x, current.y)
        context.stroke()
      }
    }

    const draw = (time = 0) => {
      context.clearRect(0, 0, width, height)
      const mobile = width < 700
      const radius = Math.min(mobile ? width * 0.4 : width * 0.245, height * 0.36)
      const centerX = width * (mobile ? 0.55 : 0.71) + pointer.x * 7
      const centerY = height * (mobile ? 0.35 : 0.48) + pointer.y * 5
      const rotation = routeRotation + (reducedMotion ? 0.5 : time * 0.000045)

      drawMesh(rotation, centerX, centerY, radius)
      drawSignals(rotation, centerX, centerY, radius)

      context.strokeStyle = 'rgba(203, 200, 210, 0.16)'
      context.lineWidth = 0.8
      context.beginPath()
      context.arc(centerX, centerY, radius + 18, -0.4, 1.08)
      context.stroke()
      context.beginPath()
      context.arc(centerX, centerY, radius + 28, 2.18, 3.46)
      context.stroke()
    }

    const animate = time => {
      if (!visible) return
      if (time - previousFrame >= 42) {
        draw(time)
        previousFrame = time
      }
      frame = window.requestAnimationFrame(animate)
    }

    const handlePointer = event => {
      pointer.x = event.clientX / Math.max(width, 1) - 0.5
      pointer.y = event.clientY / Math.max(height, 1) - 0.5
    }

    const handleVisibility = () => {
      visible = !document.hidden
      if (visible && !reducedMotion) {
        window.cancelAnimationFrame(frame)
        frame = window.requestAnimationFrame(animate)
      }
    }

    resize()
    draw()
    window.addEventListener('resize', resize, { passive: true })
    window.addEventListener('pointermove', handlePointer, { passive: true })
    document.addEventListener('visibilitychange', handleVisibility)
    if (!reducedMotion) frame = window.requestAnimationFrame(animate)

    return () => {
      window.cancelAnimationFrame(frame)
      window.removeEventListener('resize', resize)
      window.removeEventListener('pointermove', handlePointer)
      document.removeEventListener('visibilitychange', handleVisibility)
    }
  }, [scene])

  return <canvas ref={canvasRef} className="threat-field" aria-hidden="true" />
}
