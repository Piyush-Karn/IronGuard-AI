import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield } from "lucide-react";

const codeLines = [
  "$ initializing ironguard_security_module...",
  "> loading threat_detection_engine v4.2.1",
  "> connecting to neural_firewall...",
  "> importing prompt_analysis_core",
  "> calibrating anomaly_detector...",
  "> establishing secure_tunnel [TLS 1.3]",
  "> loading user_behavior_analytics...",
  "$ all modules loaded successfully ✓",
  "> launching interface...",
];

const CodeLoader = ({ onComplete }: { onComplete: () => void }) => {
  const [visibleLines, setVisibleLines] = useState(0);

  useEffect(() => {
    if (visibleLines < codeLines.length) {
      const timer = setTimeout(() => setVisibleLines((v) => v + 1), 220);
      return () => clearTimeout(timer);
    } else {
      const timer = setTimeout(onComplete, 400);
      return () => clearTimeout(timer);
    }
  }, [visibleLines, onComplete]);

  return (
    <div className="fixed inset-0 z-[100] bg-black flex items-center justify-center">
      <div className="w-full max-w-lg px-6">
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center gap-3 mb-8 justify-center"
        >
          <div className="h-10 w-10 rounded-xl bg-white/[0.06] border border-white/[0.08] flex items-center justify-center">
            <Shield className="h-5 w-5 text-white/40" />
          </div>
          <span className="text-white/60 text-sm font-semibold tracking-tight">
            IronGuard AI
          </span>
        </motion.div>

        <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5 font-mono text-xs space-y-1.5">
          {codeLines.slice(0, visibleLines).map((line, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.15 }}
              className={`${
                line.includes("✓")
                  ? "text-green-400/80"
                  : line.startsWith("$")
                  ? "text-cyan-400/60"
                  : "text-white/30"
              }`}
            >
              {line}
            </motion.div>
          ))}
          {visibleLines < codeLines.length && (
            <motion.span
              className="inline-block w-2 h-4 bg-white/40"
              animate={{ opacity: [1, 0] }}
              transition={{ duration: 0.5, repeat: Infinity }}
            />
          )}
        </div>

        <div className="mt-4 h-1 rounded-full bg-white/[0.06] overflow-hidden">
          <motion.div
            className="h-full bg-gradient-to-r from-cyan-500/60 to-white/40 rounded-full"
            initial={{ width: "0%" }}
            animate={{
              width: `${(visibleLines / codeLines.length) * 100}%`,
            }}
            transition={{ duration: 0.2 }}
          />
        </div>
      </div>
    </div>
  );
};

export default CodeLoader;
