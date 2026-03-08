import { useRef, useCallback, type ReactNode } from "react";
import { motion } from "framer-motion";

interface ElectricCardProps {
  children: ReactNode;
  className?: string;
}

const ElectricCard = ({ children, className = "" }: ElectricCardProps) => {
  const ref = useRef<HTMLDivElement>(null);
  const glowRef = useRef<HTMLDivElement>(null);
  const edgeRef = useRef<HTMLDivElement>(null);
  const rafId = useRef(0);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    cancelAnimationFrame(rafId.current);
    rafId.current = requestAnimationFrame(() => {
      if (!ref.current) return;
      const rect = ref.current.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      if (glowRef.current) {
        glowRef.current.style.background = `radial-gradient(600px circle at ${x}px ${y}px, rgba(120,119,255,0.12), transparent 40%)`;
      }
      if (edgeRef.current) {
        edgeRef.current.style.background = `radial-gradient(400px circle at ${x}px ${y}px, rgba(120,130,255,0.15), transparent 40%)`;
      }
    });
  }, []);

  const handleMouseEnter = useCallback(() => {
    if (glowRef.current) glowRef.current.style.opacity = "1";
    if (edgeRef.current) edgeRef.current.style.opacity = "1";
  }, []);

  const handleMouseLeave = useCallback(() => {
    if (glowRef.current) glowRef.current.style.opacity = "0";
    if (edgeRef.current) edgeRef.current.style.opacity = "0";
  }, []);

  return (
    <motion.div
      ref={ref}
      onMouseMove={handleMouseMove}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      whileHover={{ scale: 1.02, y: -4 }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}
      className={`relative overflow-hidden rounded-2xl bg-white/[0.03] border border-white/[0.06] will-change-transform ${className}`}
    >
      <div
        ref={glowRef}
        className="absolute inset-0 rounded-2xl opacity-0 transition-opacity duration-700 pointer-events-none"
      />
      <div
        ref={edgeRef}
        className="absolute -inset-px rounded-2xl opacity-0 transition-opacity duration-500 pointer-events-none"
        style={{
          mask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
          WebkitMask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
          maskComposite: "exclude",
          WebkitMaskComposite: "xor",
          padding: "1px",
        }}
      />
      <div className="relative z-10">{children}</div>
    </motion.div>
  );
};

export default ElectricCard;
