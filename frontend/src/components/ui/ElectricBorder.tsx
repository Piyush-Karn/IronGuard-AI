import { useRef, useEffect, useState, type ReactNode, type CSSProperties } from "react";
import "./ElectricBorder.css";

interface ElectricBorderProps {
  children?: ReactNode;
  color?: string;
  speed?: number;
  chaos?: number;
  borderRadius?: number;
  className?: string;
  style?: CSSProperties;
}

function noise(x: number, y: number, t: number): number {
  const s = Math.sin(x * 12.9898 + y * 78.233 + t) * 43758.5453;
  return s - Math.floor(s);
}

function smoothNoise(x: number, y: number, t: number): number {
  const ix = Math.floor(x);
  const iy = Math.floor(y);
  const fx = x - ix;
  const fy = y - iy;
  const sx = fx * fx * (3 - 2 * fx);
  const sy = fy * fy * (3 - 2 * fy);
  const n00 = noise(ix, iy, t);
  const n10 = noise(ix + 1, iy, t);
  const n01 = noise(ix, iy + 1, t);
  const n11 = noise(ix + 1, iy + 1, t);
  const nx0 = n00 * (1 - sx) + n10 * sx;
  const nx1 = n01 * (1 - sx) + n11 * sx;
  return nx0 * (1 - sy) + nx1 * sy;
}

function fbm(x: number, y: number, t: number, octaves: number): number {
  let value = 0;
  let amplitude = 0.5;
  let frequency = 1;
  for (let i = 0; i < octaves; i++) {
    value += amplitude * smoothNoise(x * frequency, y * frequency, t + i * 100);
    amplitude *= 0.5;
    frequency *= 2;
  }
  return value;
}

function hexToRgb(hex: string): [number, number, number] {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  if (!result) return [125, 249, 255];
  return [parseInt(result[1], 16), parseInt(result[2], 16), parseInt(result[3], 16)];
}

const ElectricBorder = ({
  children,
  color = "#7df9ff",
  speed = 1,
  chaos = 0.15,
  borderRadius = 16,
  className = "",
  style,
}: ElectricBorderProps) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const animRef = useRef<number>(0);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => setIsVisible(entry.isIntersecting),
      { threshold: 0.05, rootMargin: "100px" }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container || !isVisible) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const padding = 10;
    const [r, g, b] = hexToRgb(color);
    let time = 0;

    const resize = () => {
      const rect = container.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio, 1.5);
      const w = rect.width + padding * 2;
      const h = rect.height + padding * 2;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();

    const observer = new ResizeObserver(resize);
    observer.observe(container);

    const drawElectricBorder = () => {
      const w = parseFloat(canvas.style.width);
      const h = parseFloat(canvas.style.height);
      ctx.clearRect(0, 0, w, h);

      const br = borderRadius + padding * 0.5;
      const perimeter = 2 * (w + h - 4 * br) + 2 * Math.PI * br;
      const steps = Math.max(200, Math.floor(perimeter / 2.5));

      const points: [number, number][] = [];
      for (let i = 0; i <= steps; i++) {
        const t = i / steps;
        const dist = t * perimeter;
        let px = 0, py = 0;
        const top = w - 2 * br;
        const right = h - 2 * br;
        const bottom = w - 2 * br;
        const left = h - 2 * br;
        const corner = (Math.PI / 2) * br;

        let d = dist;
        if (d < top) { px = br + d; py = 0; }
        else if ((d -= top) < corner) { const a = d / br; px = w - br + Math.sin(a) * br; py = br - Math.cos(a) * br; }
        else if ((d -= corner) < right) { px = w; py = br + d; }
        else if ((d -= right) < corner) { const a = d / br; px = w - br + Math.cos(a) * br; py = h - br + Math.sin(a) * br; }
        else if ((d -= corner) < bottom) { px = w - br - d; py = h; }
        else if ((d -= bottom) < corner) { const a = d / br; px = br - Math.sin(a) * br; py = h - br + Math.cos(a) * br; }
        else if ((d -= corner) < left) { px = 0; py = h - br - d; }
        else { d -= left; const a = d / br; px = br - Math.cos(a) * br; py = br - Math.sin(a) * br; }

        // Stronger displacement for jagged electric look
        const noiseVal = fbm(t * 10, time * speed * 0.6, time * speed, 3);
        const displacement = (noiseVal - 0.5) * chaos * 80;
        const cx = w / 2, cy = h / 2;
        const dx = px - cx, dy = py - cy;
        const len = Math.sqrt(dx * dx + dy * dy) || 1;
        px += (dx / len) * displacement;
        py += (dy / len) * displacement;
        points.push([px, py]);
      }

      // Layer 1: Wide outer glow
      ctx.save();
      ctx.filter = "blur(8px)";
      ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, 0.15)`;
      ctx.lineWidth = 6;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.beginPath();
      for (let i = 0; i < points.length; i++) {
        const [px, py] = points[i];
        if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.stroke();
      ctx.restore();

      // Layer 2: Medium glow
      ctx.save();
      ctx.filter = "blur(3px)";
      ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, 0.4)`;
      ctx.lineWidth = 2.5;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.beginPath();
      for (let i = 0; i < points.length; i++) {
        const [px, py] = points[i];
        if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.stroke();
      ctx.restore();

      // Layer 3: Sharp core line
      ctx.save();
      ctx.filter = "none";
      ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, 0.9)`;
      ctx.lineWidth = 1.2;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.beginPath();
      for (let i = 0; i < points.length; i++) {
        const [px, py] = points[i];
        if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.stroke();
      ctx.restore();

      // Traveling energy pulse
      const pulsePos = ((time * speed * 0.3) % 1);
      const pulseIdx = Math.floor(pulsePos * points.length);
      const pulseLen = 30;
      ctx.save();
      for (let i = 0; i < pulseLen; i++) {
        const idx = (pulseIdx + i) % points.length;
        const [px, py] = points[idx];
        const a = (1 - i / pulseLen) * 0.9;
        const size = (1 - i / pulseLen) * 4;
        ctx.beginPath();
        ctx.arc(px, py, size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${Math.min(r + 80, 255)}, ${Math.min(g + 80, 255)}, ${Math.min(b + 80, 255)}, ${a})`;
        ctx.shadowColor = `rgba(${r}, ${g}, ${b}, 0.6)`;
        ctx.shadowBlur = 8;
        ctx.fill();
      }
      ctx.restore();

      time += 0.016;
      animRef.current = requestAnimationFrame(drawElectricBorder);
    };

    drawElectricBorder();

    return () => {
      cancelAnimationFrame(animRef.current);
      observer.disconnect();
    };
  }, [color, speed, chaos, borderRadius, isVisible]);

  return (
    <div ref={containerRef} className={`electric-border ${className}`} style={{ borderRadius, ...style }}>
      <div className="eb-canvas-container">
        <canvas ref={canvasRef} className="eb-canvas" />
      </div>
      <div className="eb-layers" style={{ borderRadius }}>
        <div className="eb-glow-1" style={{ borderColor: `${color}99`, borderRadius }} />
        <div className="eb-glow-2" style={{ borderColor: color, borderRadius }} />
        <div className="eb-background-glow" style={{ borderRadius }} />
      </div>
      <div className="eb-content" style={{ borderRadius }}>{children}</div>
    </div>
  );
};

export default ElectricBorder;
