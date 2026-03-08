import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Shield } from "lucide-react";

const bootLines = [
  { text: "[BIOS] IronGuard Security Module v4.2.1", delay: 0 },
  { text: "[BOOT] Initializing neural defense matrix...", delay: 180 },
  { text: "[SYS ] Loading threat signature database ████████ 100%", delay: 300 },
  { text: "[NET ] Establishing encrypted tunnel... OK", delay: 180 },
  { text: "[CORE] Prompt injection firewall — ARMED", delay: 200 },
  { text: "[CORE] Jailbreak detection engine — ARMED", delay: 150 },
  { text: "[CORE] Data exfiltration shield — ARMED", delay: 150 },
  { text: "[SCAN] Running system integrity check...", delay: 250 },
  { text: "[  OK] All 47 security modules verified", delay: 200 },
  { text: "[SYS ] IronGuard AI — ONLINE", delay: 300 },
];

const glitchChars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";

const GlitchText = ({ text, active }: { text: string; active: boolean }) => {
  const [display, setDisplay] = useState(text);

  useEffect(() => {
    if (!active) { setDisplay(text); return; }
    let frame = 0;
    const maxFrames = 4;
    const interval = setInterval(() => {
      if (frame >= maxFrames) { setDisplay(text); clearInterval(interval); return; }
      setDisplay(
        text.split("").map((c, i) =>
          Math.random() < 0.3 ? glitchChars[Math.floor(Math.random() * glitchChars.length)] : c
        ).join("")
      );
      frame++;
    }, 50);
    return () => clearInterval(interval);
  }, [text, active]);

  return <span>{display}</span>;
};

const CyberBootLoader = ({ onComplete }: { onComplete: () => void }) => {
  const [visibleLines, setVisibleLines] = useState(0);
  const [glitchLine, setGlitchLine] = useState(-1);
  const [screenGlitch, setScreenGlitch] = useState(false);
  const [fadeOut, setFadeOut] = useState(false);

  useEffect(() => {
    if (visibleLines < bootLines.length) {
      const delay = bootLines[visibleLines]?.delay || 200;
      const timer = setTimeout(() => {
        setGlitchLine(visibleLines);
        setVisibleLines((v) => v + 1);
        // Random screen glitch
        if (Math.random() < 0.3) {
          setScreenGlitch(true);
          setTimeout(() => setScreenGlitch(false), 100);
        }
      }, delay);
      return () => clearTimeout(timer);
    } else {
      const timer = setTimeout(() => {
        setScreenGlitch(true);
        setTimeout(() => {
          setScreenGlitch(false);
          setFadeOut(true);
          setTimeout(onComplete, 600);
        }, 150);
      }, 500);
      return () => clearTimeout(timer);
    }
  }, [visibleLines, onComplete]);

  return (
    <AnimatePresence>
      {!fadeOut ? (
        <motion.div
          exit={{ opacity: 0 }}
          transition={{ duration: 0.5 }}
          className="fixed inset-0 z-[100] bg-black flex flex-col items-center justify-center overflow-hidden"
          style={{
            transform: screenGlitch
              ? `translate(${Math.random() * 6 - 3}px, ${Math.random() * 4 - 2}px) skewX(${Math.random() * 2 - 1}deg)`
              : "none",
          }}
        >
          {/* Scanlines overlay */}
          <div
            className="absolute inset-0 pointer-events-none opacity-[0.04]"
            style={{
              backgroundImage:
                "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.03) 2px, rgba(255,255,255,0.03) 4px)",
            }}
          />

          {/* CRT vignette */}
          <div
            className="absolute inset-0 pointer-events-none"
            style={{
              background:
                "radial-gradient(ellipse at center, transparent 50%, rgba(0,0,0,0.6) 100%)",
            }}
          />

          {/* Glitch color split */}
          {screenGlitch && (
            <div className="absolute inset-0 pointer-events-none mix-blend-screen">
              <div className="absolute inset-0 bg-cyan-500/10 translate-x-1" />
              <div className="absolute inset-0 bg-red-500/10 -translate-x-1" />
            </div>
          )}

          {/* Logo */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.3 }}
            className="mb-8 flex items-center gap-3"
          >
            <div className="h-10 w-10 rounded-xl bg-white/[0.04] border border-white/[0.08] flex items-center justify-center">
              <Shield className="h-5 w-5 text-cyan-400/60" />
            </div>
            <span className="text-cyan-400/50 text-xs font-mono tracking-[0.3em] uppercase">
              IronGuard
            </span>
          </motion.div>

          {/* Boot log */}
          <div className="w-full max-w-xl px-6 font-mono text-[11px] leading-relaxed space-y-1">
            {bootLines.slice(0, visibleLines).map((line, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -4 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.1 }}
                className={`${
                  line.text.includes("ARMED")
                    ? "text-green-400/70"
                    : line.text.includes("ONLINE")
                    ? "text-cyan-400/90 font-bold"
                    : line.text.includes("OK")
                    ? "text-green-400/50"
                    : "text-white/25"
                }`}
              >
                <GlitchText text={line.text} active={i === glitchLine} />
              </motion.div>
            ))}

            {/* Blinking cursor */}
            {visibleLines < bootLines.length && (
              <motion.span
                className="inline-block w-2 h-3.5 bg-cyan-400/50 ml-0.5"
                animate={{ opacity: [1, 0] }}
                transition={{ duration: 0.4, repeat: Infinity }}
              />
            )}
          </div>

          {/* Progress bar */}
          <div className="mt-8 w-full max-w-xl px-6">
            <div className="h-px bg-white/[0.06] overflow-hidden rounded-full">
              <motion.div
                className="h-full bg-gradient-to-r from-cyan-500/40 to-cyan-400/60"
                initial={{ width: "0%" }}
                animate={{
                  width: `${(visibleLines / bootLines.length) * 100}%`,
                }}
                transition={{ duration: 0.15 }}
              />
            </div>
          </div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
};

export default CyberBootLoader;
