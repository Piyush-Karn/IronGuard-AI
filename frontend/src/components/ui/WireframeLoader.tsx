import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { motion, AnimatePresence } from "framer-motion";
import * as THREE from "three";

// Wireframe shield geometry - icosahedron with particles
const WireframeShield = ({ progress }: { progress: number }) => {
  const meshRef = useRef<THREE.Group>(null);
  const particlesRef = useRef<THREE.Points>(null);
  const ringRef = useRef<THREE.Mesh>(null);

  const particlePositions = useMemo(() => {
    const positions = new Float32Array(200 * 3);
    for (let i = 0; i < 200; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      const r = 3 + Math.random() * 4;
      positions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      positions[i * 3 + 2] = r * Math.cos(phi);
    }
    return positions;
  }, []);

  const targetPositions = useMemo(() => {
    const positions = new Float32Array(200 * 3);
    const geo = new THREE.IcosahedronGeometry(1.2, 1);
    const verts = geo.attributes.position.array;
    for (let i = 0; i < 200; i++) {
      const vi = (i % (verts.length / 3)) * 3;
      positions[i * 3] = verts[vi] + (Math.random() - 0.5) * 0.1;
      positions[i * 3 + 1] = verts[vi + 1] + (Math.random() - 0.5) * 0.1;
      positions[i * 3 + 2] = verts[vi + 2] + (Math.random() - 0.5) * 0.1;
    }
    return positions;
  }, []);

  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.y += 0.008;
      meshRef.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.5) * 0.1;
    }
    if (ringRef.current) {
      ringRef.current.rotation.z += 0.015;
    }
    if (particlesRef.current) {
      const positions = particlesRef.current.geometry.attributes.position.array as Float32Array;
      for (let i = 0; i < 200; i++) {
        const i3 = i * 3;
        positions[i3] = THREE.MathUtils.lerp(particlePositions[i3], targetPositions[i3], progress);
        positions[i3 + 1] = THREE.MathUtils.lerp(particlePositions[i3 + 1], targetPositions[i3 + 1], progress);
        positions[i3 + 2] = THREE.MathUtils.lerp(particlePositions[i3 + 2], targetPositions[i3 + 2], progress);
      }
      particlesRef.current.geometry.attributes.position.needsUpdate = true;
    }
  });

  return (
    <group ref={meshRef}>
      {/* Wireframe icosahedron */}
      <mesh scale={progress > 0.3 ? 1 : 0}>
        <icosahedronGeometry args={[1.2, 1]} />
        <meshBasicMaterial
          color="#00e5ff"
          wireframe
          transparent
          opacity={Math.min(1, progress * 2) * 0.4}
        />
      </mesh>

      {/* Inner glow */}
      <mesh scale={progress > 0.5 ? 0.8 : 0}>
        <icosahedronGeometry args={[1, 0]} />
        <meshBasicMaterial
          color="#00e5ff"
          transparent
          opacity={Math.max(0, (progress - 0.5) * 0.3)}
        />
      </mesh>

      {/* Scanning ring */}
      <mesh ref={ringRef} scale={progress > 0.2 ? 1 : 0}>
        <torusGeometry args={[1.8, 0.01, 8, 64]} />
        <meshBasicMaterial color="#00e5ff" transparent opacity={progress * 0.5} />
      </mesh>

      {/* Second ring */}
      <mesh rotation={[Math.PI / 3, 0, 0]} scale={progress > 0.4 ? 1 : 0}>
        <torusGeometry args={[2.0, 0.008, 8, 64]} />
        <meshBasicMaterial color="#00bcd4" transparent opacity={progress * 0.3} />
      </mesh>

      {/* Particles */}
      <points ref={particlesRef}>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            count={200}
            array={particlePositions}
            itemSize={3}
          />
        </bufferGeometry>
        <pointsMaterial
          color="#00e5ff"
          size={0.04}
          transparent
          opacity={0.7}
          sizeAttenuation
        />
      </points>
    </group>
  );
};

const WireframeLoader = ({ onComplete }: { onComplete: () => void }) => {
  const [progress, setProgress] = useState(0);
  const [fadeOut, setFadeOut] = useState(false);
  const [statusText, setStatusText] = useState("Assembling security matrix...");

  useEffect(() => {
    const duration = 3000;
    const start = Date.now();
    const interval = setInterval(() => {
      const elapsed = Date.now() - start;
      const p = Math.min(1, elapsed / duration);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - p, 3);
      setProgress(eased);

      if (eased > 0.3 && eased < 0.6) setStatusText("Calibrating threat vectors...");
      else if (eased > 0.6 && eased < 0.85) setStatusText("Initializing defense grid...");
      else if (eased > 0.85) setStatusText("IronGuard ready");

      if (p >= 1) {
        clearInterval(interval);
        setTimeout(() => {
          setFadeOut(true);
          setTimeout(onComplete, 600);
        }, 400);
      }
    }, 16);
    return () => clearInterval(interval);
  }, [onComplete]);

  return (
    <AnimatePresence>
      {!fadeOut ? (
        <motion.div
          exit={{ opacity: 0 }}
          transition={{ duration: 0.5 }}
          className="fixed inset-0 z-[100] bg-black flex flex-col items-center justify-center"
        >
          {/* 3D Canvas */}
          <div className="w-64 h-64 md:w-80 md:h-80">
            <Canvas camera={{ position: [0, 0, 4.5], fov: 45 }}>
              <ambientLight intensity={0.2} />
              <WireframeShield progress={progress} />
            </Canvas>
          </div>

          {/* Status text */}
          <motion.p
            key={statusText}
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-cyan-400/50 text-xs font-mono tracking-widest mt-4"
          >
            {statusText}
          </motion.p>

          {/* Progress bar */}
          <div className="mt-6 w-48 h-px bg-white/[0.06] overflow-hidden rounded-full">
            <motion.div
              className="h-full bg-gradient-to-r from-cyan-500/40 to-cyan-400/70"
              style={{ width: `${progress * 100}%` }}
            />
          </div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
};

export default WireframeLoader;
