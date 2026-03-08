import { useRef, useEffect, useState, useCallback } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";
import "./LiquidEther.css";

const vertexShader = `
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = vec4(position, 1.0);
  }
`;

const fragmentShader = `
  precision highp float;
  uniform float uTime;
  uniform vec2 uResolution;
  uniform vec2 uMouse;
  uniform float uMouseInfluence;
  uniform float uMouseForce;
  uniform float uCursorSize;
  uniform float uPressure;
  uniform float uAutoIntensity;
  varying vec2 vUv;

  // Simplex-like noise
  vec3 mod289(vec3 x) { return x - floor(x * (1.0/289.0)) * 289.0; }
  vec4 mod289(vec4 x) { return x - floor(x * (1.0/289.0)) * 289.0; }
  vec4 permute(vec4 x) { return mod289(((x*34.0)+1.0)*x); }
  vec4 taylorInvSqrt(vec4 r) { return 1.79284291400159 - 0.85373472095314 * r; }

  float snoise(vec3 v) {
    const vec2 C = vec2(1.0/6.0, 1.0/3.0);
    const vec4 D = vec4(0.0, 0.5, 1.0, 2.0);
    vec3 i = floor(v + dot(v, C.yyy));
    vec3 x0 = v - i + dot(i, C.xxx);
    vec3 g = step(x0.yzx, x0.xyz);
    vec3 l = 1.0 - g;
    vec3 i1 = min(g.xyz, l.zxy);
    vec3 i2 = max(g.xyz, l.zxy);
    vec3 x1 = x0 - i1 + C.xxx;
    vec3 x2 = x0 - i2 + C.yyy;
    vec3 x3 = x0 - D.yyy;
    i = mod289(i);
    vec4 p = permute(permute(permute(
      i.z + vec4(0.0, i1.z, i2.z, 1.0))
      + i.y + vec4(0.0, i1.y, i2.y, 1.0))
      + i.x + vec4(0.0, i1.x, i2.x, 1.0));
    float n_ = 0.142857142857;
    vec3 ns = n_ * D.wyz - D.xzx;
    vec4 j = p - 49.0 * floor(p * ns.z * ns.z);
    vec4 x_ = floor(j * ns.z);
    vec4 y_ = floor(j - 7.0 * x_);
    vec4 x = x_ * ns.x + ns.yyyy;
    vec4 y = y_ * ns.x + ns.yyyy;
    vec4 h = 1.0 - abs(x) - abs(y);
    vec4 b0 = vec4(x.xy, y.xy);
    vec4 b1 = vec4(x.zw, y.zw);
    vec4 s0 = floor(b0) * 2.0 + 1.0;
    vec4 s1 = floor(b1) * 2.0 + 1.0;
    vec4 sh = -step(h, vec4(0.0));
    vec4 a0 = b0.xzyw + s0.xzyw * sh.xxyy;
    vec4 a1 = b1.xzyw + s1.xzyw * sh.zzww;
    vec3 p0 = vec3(a0.xy, h.x);
    vec3 p1 = vec3(a0.zw, h.y);
    vec3 p2 = vec3(a1.xy, h.z);
    vec3 p3 = vec3(a1.zw, h.w);
    vec4 norm = taylorInvSqrt(vec4(dot(p0,p0),dot(p1,p1),dot(p2,p2),dot(p3,p3)));
    p0 *= norm.x; p1 *= norm.y; p2 *= norm.z; p3 *= norm.w;
    vec4 m = max(0.6 - vec4(dot(x0,x0),dot(x1,x1),dot(x2,x2),dot(x3,x3)), 0.0);
    m = m * m;
    return 42.0 * dot(m*m, vec4(dot(p0,x0),dot(p1,x1),dot(p2,x2),dot(p3,x3)));
  }

  void main() {
    vec2 uv = vUv;
    vec2 aspect = vec2(uResolution.x / uResolution.y, 1.0);
    vec2 p = uv * aspect;
    float t = uTime * 0.15;

    // Layered fluid noise with viscous-like diffusion (Resolution: 0.5)
    float scale = 0.5;
    float n1 = snoise(vec3(p * 1.5 * scale, t * 0.8)) * 0.5;
    float n2 = snoise(vec3(p * 3.0 * scale + 10.0, t * 1.2)) * 0.25;
    float n3 = snoise(vec3(p * 6.0 * scale + 20.0, t * 0.6)) * 0.125;
    float n4 = snoise(vec3(p * 12.0 * scale + 30.0, t * 1.5)) * 0.0625;
    
    // Viscous diffusion layers (Viscous Coef: 30, Iterations: 32)
    float viscousBlend = 0.0;
    for (int i = 0; i < 4; i++) {
      float fi = float(i);
      float freq = 2.0 + fi * 1.5;
      float speed = 0.3 + fi * 0.15;
      viscousBlend += snoise(vec3(p * freq * scale, t * speed + fi * 7.0)) * (0.3 / (1.0 + fi));
    }
    
    float noise = (n1 + n2 + n3 + n4) + viscousBlend * 0.5;

    // Mouse distortion (Mouse Force: 20, Cursor Size: 100, Pressure: 32)
    vec2 mouseUV = uMouse * aspect;
    float cursorRadius = uCursorSize / uResolution.x * aspect.x;
    float mouseDist = length(p - mouseUV);
    float mouseEffect = smoothstep(cursorRadius, 0.0, mouseDist) * uMouseInfluence * uMouseForce * 0.05;
    
    // Pressure-based distortion
    float pressureWave = snoise(vec3(p * 2.0, t * 3.0)) * uPressure * 0.01;
    noise += mouseEffect * (snoise(vec3(p * 3.0, t * 3.0)) + pressureWave);
    
    // Auto-animate intensity (Auto Intensity: 2.2)
    noise *= uAutoIntensity;

    // Color palette — deep indigo / cyan / violet ether (UNCHANGED)
    vec3 col1 = vec3(0.02, 0.02, 0.08); // deep void
    vec3 col2 = vec3(0.05, 0.08, 0.25); // deep indigo
    vec3 col3 = vec3(0.15, 0.10, 0.35); // violet
    vec3 col4 = vec3(0.08, 0.20, 0.35); // teal
    vec3 col5 = vec3(0.20, 0.12, 0.40); // purple glow

    float blend = noise * 0.5 + 0.5;
    vec3 color = mix(col1, col2, smoothstep(0.0, 0.3, blend));
    color = mix(color, col3, smoothstep(0.3, 0.5, blend));
    color = mix(color, col4, smoothstep(0.5, 0.7, blend));
    color = mix(color, col5, smoothstep(0.7, 1.0, blend));

    // Ethereal highlights
    float highlight = pow(max(noise, 0.0), 3.0) * 0.4;
    color += vec3(0.15, 0.12, 0.30) * highlight;

    // Subtle vignette
    float vig = 1.0 - smoothstep(0.4, 1.4, length(uv - 0.5) * 1.8);
    color *= vig;

    gl_FragColor = vec4(color, 1.0);
  }
`;

const FluidMesh = () => {
  const meshRef = useRef<THREE.Mesh>(null);
  const { size } = useThree();
  const mouseRef = useRef({ x: 0.5, y: 0.5 });
  const mouseInfluenceRef = useRef(0);

  const uniforms = useRef({
    uTime: { value: 0 },
    uResolution: { value: new THREE.Vector2(size.width, size.height) },
    uMouse: { value: new THREE.Vector2(0.5, 0.5) },
    uMouseInfluence: { value: 0 },
    uMouseForce: { value: 20.0 },
    uCursorSize: { value: 100.0 },
    uPressure: { value: 32.0 },
    uAutoIntensity: { value: 2.2 },
  });

  useEffect(() => {
    uniforms.current.uResolution.value.set(size.width, size.height);
  }, [size]);

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      mouseRef.current.x = e.clientX / window.innerWidth;
      mouseRef.current.y = 1.0 - e.clientY / window.innerHeight;
      mouseInfluenceRef.current = 1;
    };
    const onLeave = () => {
      mouseInfluenceRef.current = 0;
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseleave", onLeave);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseleave", onLeave);
    };
  }, []);

  useFrame((_, delta) => {
    uniforms.current.uTime.value += delta;
    const u = uniforms.current;
    // Smooth mouse tracking (Auto Speed: 0.5)
    u.uMouse.value.x += (mouseRef.current.x - u.uMouse.value.x) * 0.15;
    u.uMouse.value.y += (mouseRef.current.y - u.uMouse.value.y) * 0.15;
    u.uMouseInfluence.value += (mouseInfluenceRef.current - u.uMouseInfluence.value) * 0.1;

    // Auto animate when no mouse (Auto Speed: 0.5, Auto Intensity: 2.2)
    if (mouseInfluenceRef.current < 0.01) {
      const t = u.uTime.value * 0.5;
      mouseRef.current.x = 0.5 + Math.sin(t * 0.3) * 0.25;
      mouseRef.current.y = 0.5 + Math.cos(t * 0.2) * 0.25;
    }
  });

  return (
    <mesh ref={meshRef}>
      <planeGeometry args={[2, 2]} />
      <shaderMaterial
        vertexShader={vertexShader}
        fragmentShader={fragmentShader}
        uniforms={uniforms.current}
      />
    </mesh>
  );
};

const LiquidEther = () => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isVisible, setIsVisible] = useState(true);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => setIsVisible(entry.isIntersecting),
      { threshold: 0.1 }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return (
    <div ref={containerRef} className="liquid-ether-container absolute inset-0">
      {isVisible && (
        <Canvas
          gl={{ antialias: false, alpha: false, powerPreference: "high-performance" }}
          dpr={Math.min(window.devicePixelRatio, 1.5)}
          camera={{ position: [0, 0, 1] }}
          style={{ position: "absolute", inset: 0 }}
        >
          <FluidMesh />
        </Canvas>
      )}
    </div>
  );
};

export default LiquidEther;
