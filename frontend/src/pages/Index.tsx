import React, { useEffect, useState, useRef, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import CodeLoader from "@/components/ui/CodeLoader";
import WireframeLoader from "@/components/ui/WireframeLoader";
import { motion, useScroll, useTransform, useInView, useMotionValue, useSpring, animate } from "framer-motion";
import { Shield, Zap, Users, FileText, Activity, ArrowRight, Lock, Eye, AlertTriangle, ChevronDown, Terminal, BarChart3, Scan } from "lucide-react";
import { Button } from "@/components/ui/button";
import Lenis from "lenis";
import LiquidEther from "@/components/ui/LiquidEther";
import ElectricBorder from "@/components/ui/ElectricBorder";
import ChromaGrid from "@/components/ui/ChromaGrid";
import ParticleField from "@/components/ui/ParticleField";
import ShinyText from "@/components/ui/ShinyText";
import FloatingBlobs from "@/components/ui/FloatingBlobs";
import GradualBlur from "@/components/ui/GradualBlur";
import DecryptedText from "@/components/ui/DecryptedText";
import GatewayVisualizer from "@/components/GatewayVisualizer";

const typingPhrases = [
  "Detecting Prompt Injection",
  "Monitoring AI Security",
  "Blocking Malicious Prompts",
  "Protecting LLM Infrastructure",
  "Real-Time Threat Detection",
  "AI Security Intelligence",
];

const features = [
  { icon: Shield, title: "Prompt Injection Detection", desc: "Detect and block malicious prompt injection attempts before they reach your AI models." },
  { icon: BarChart3, title: "Threat Score Monitoring", desc: "Assign dynamic threat scores to every user and prompt interaction in real-time." },
  { icon: Activity, title: "Real-Time Attack Monitoring", desc: "Live SOC-style dashboard monitoring attacks as they happen across your infrastructure." },
  { icon: Lock, title: "AI Security Firewall", desc: "Multi-layered defense system that filters every prompt before it reaches your LLM." },
  { icon: Users, title: "User Behavior Tracking", desc: "Monitor user patterns and automatically flag suspicious behavioral anomalies." },
  { icon: FileText, title: "Security Logs & Alerts", desc: "Comprehensive audit trail with instant alerts for every analyzed prompt." },
];

const steps = [
  { icon: Terminal, label: "User Prompt", sub: "Input received", num: "01" },
  { icon: Shield, label: "IronGuard Security Filter", sub: "Multi-layer scan", num: "02" },
  { icon: AlertTriangle, label: "Threat Detection Engine", sub: "AI analysis", num: "03" },
  { icon: Lock, label: "Safe AI Response", sub: "Verified output", num: "04" },
];

const attackLogs = [
  { time: "12:41:03", ip: "192.168.1.47", user: "session_a8f2", status: "SAFE PROMPT — Standard query processed", type: "safe", severity: "LOW" },
  { time: "12:41:18", ip: "10.0.3.112", user: "session_c4d1", status: "⚠ PROMPT INJECTION ATTEMPT DETECTED — Payload contains escape sequence", type: "danger", severity: "CRITICAL" },
  { time: "12:41:32", ip: "172.16.0.89", user: "session_f7a9", status: "BLOCKED — Suspicious query pattern identified: recursive jailbreak", type: "danger", severity: "HIGH" },
  { time: "12:41:45", ip: "10.0.7.203", user: "session_b2e5", status: "⚠ DATA EXTRACTION ATTEMPT — Payload blocked at layer 3", type: "warning", severity: "HIGH" },
  { time: "12:42:01", ip: "192.168.4.15", user: "session_d9c3", status: "SAFE PROMPT — Verified clean input", type: "safe", severity: "LOW" },
  { time: "12:42:14", ip: "10.0.1.67", user: "session_e1b8", status: "⚠ SECURITY LAYER ACTIVATED — DAN-style bypass attempt neutralized", type: "danger", severity: "CRITICAL" },
  { time: "12:42:28", ip: "172.16.2.44", user: "session_a3f6", status: "SAFE PROMPT — Standard query processed", type: "safe", severity: "LOW" },
  { time: "12:42:41", ip: "10.0.9.156", user: "session_g5h2", status: "BLOCKED — Obfuscated instruction injection detected", type: "danger", severity: "HIGH" },
  { time: "12:42:55", ip: "192.168.8.91", user: "session_k7m4", status: "⚠ ROLE MANIPULATION DETECTED — System prompt override attempt", type: "warning", severity: "CRITICAL" },
  { time: "12:43:08", ip: "10.0.5.33", user: "session_n2p6", status: "SAFE PROMPT — Verified clean input", type: "safe", severity: "LOW" },
];

const dashboardStats = [
  { label: "Total Users", value: "2,847", change: "+12%" },
  { label: "Prompts Analyzed", value: "48,392", change: "+8%" },
  { label: "Threat Level", value: "Medium", change: "Stable" },
  { label: "Blocked Attacks", value: "1,284", change: "+23%" },
];

const TypingText = () => {
  const [phraseIdx, setPhraseIdx] = useState(0);
  const [charIdx, setCharIdx] = useState(0);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const phrase = typingPhrases[phraseIdx];
    const timeout = deleting ? 30 : 60;

    if (!deleting && charIdx === phrase.length) {
      setTimeout(() => setDeleting(true), 2000);
      return;
    }
    if (deleting && charIdx === 0) {
      setDeleting(false);
      setPhraseIdx((p) => (p + 1) % typingPhrases.length);
      return;
    }

    const timer = setTimeout(() => {
      setCharIdx((c) => c + (deleting ? -1 : 1));
    }, timeout);
    return () => clearTimeout(timer);
  }, [charIdx, deleting, phraseIdx]);

  return (
    <span className="text-white/90">
      {typingPhrases[phraseIdx].slice(0, charIdx)}
      <span className="animate-pulse text-white">|</span>
    </span>
  );
};

// Animated counter component
const AnimatedCounter = ({ target, suffix = "", duration = 2 }: { target: number; suffix?: string; duration?: number }) => {
  const ref = useRef<HTMLSpanElement>(null);
  const isInView = useInView(ref, { once: true, margin: "-100px" });
  const [displayed, setDisplayed] = useState(0);

  useEffect(() => {
    if (!isInView) return;
    const controls = animate(0, target, {
      duration,
      ease: "easeOut",
      onUpdate: (v) => setDisplayed(Math.floor(v)),
    });
    return () => controls.stop();
  }, [isInView, target, duration]);

  return <span ref={ref}>{displayed.toLocaleString()}{suffix}</span>;
};

// Terminal typing log line
const TerminalLogLine = React.memo(({ log }: { log: typeof attackLogs[0] }) => {
  const [typedChars, setTypedChars] = useState(0);
  const fullText = log.status;
  const rafRef = useRef(0);

  useEffect(() => {
    setTypedChars(0);
    let i = 0;
    let lastTime = 0;
    const step = (time: number) => {
      if (time - lastTime >= 12) {
        lastTime = time;
        i++;
        setTypedChars(i);
      }
      if (i < fullText.length) {
        rafRef.current = requestAnimationFrame(step);
      }
    };
    rafRef.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(rafRef.current);
  }, [fullText]);

  const severityColor = log.severity === "CRITICAL" ? "text-red-500" : log.severity === "HIGH" ? "text-orange-400" : "text-green-400";

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="flex items-start gap-2 py-2 px-3 rounded-lg hover:bg-white/[0.03] transition-colors duration-300 group will-change-transform"
    >
      <span className="text-white/15 shrink-0 text-xs">[{log.time}]</span>
      <span className="text-white/25 shrink-0 text-xs">{log.ip}</span>
      <span className="text-cyan-400/50 shrink-0 text-xs">{log.user}</span>
      <span className="text-white/10">│</span>
      <span className={`text-xs flex-1 ${
        log.type === "safe" ? "text-green-400/80" :
        log.type === "warning" ? "text-yellow-400/80" :
        "text-red-400/90"
      }`}>
        {fullText.slice(0, typedChars)}
        {typedChars < fullText.length && <span className="animate-pulse text-white/60">▊</span>}
      </span>
      <span className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 ${severityColor} bg-current/10 font-medium`}
        style={{ backgroundColor: log.severity === "CRITICAL" ? "rgba(239,68,68,0.1)" : log.severity === "HIGH" ? "rgba(251,146,60,0.1)" : "rgba(74,222,128,0.1)" }}>
        {log.severity}
      </span>
      {(log.type === "danger" || log.type === "warning") && (
        <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse shrink-0 mt-1 shadow-[0_0_8px_rgba(239,68,68,0.6)]" />
      )}
    </motion.div>
  );
});

// fadeUp is now defined inside the component as smoothReveal

const scaleStats = [
  { label: "Prompts Scanned", target: 12400000, suffix: "+", icon: Scan },
  { label: "Threats Blocked", target: 847000, suffix: "+", icon: Shield },
  { label: "Avg Response", target: 12, suffix: "ms", icon: Zap },
  { label: "Uptime", target: 99, suffix: ".99%", icon: Activity },
];

const Index = () => {
  const containerRef = useRef<HTMLDivElement>(null);
  const lenisRef = useRef<Lenis | null>(null);
  const navigate = useNavigate();
  const [showLoader, setShowLoader] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);

  const handleInitialLoadComplete = useCallback(() => setInitialLoading(false), []);

  const handleGetStarted = useCallback(() => {
    setShowLoader(true);
  }, []);

  const handleLoaderComplete = useCallback(() => {
    navigate("/login");
  }, [navigate]);
  const { scrollYProgress } = useScroll();
  
  // Spring-smoothed parallax values for GPU-accelerated motion
  const heroYRaw = useTransform(scrollYProgress, [0, 0.25], [0, -80]);
  const heroY = useSpring(heroYRaw, { stiffness: 80, damping: 30, mass: 0.8 });
  const heroOpacity = useTransform(scrollYProgress, [0, 0.18], [1, 0]);
  const heroOpacitySmooth = useSpring(heroOpacity, { stiffness: 80, damping: 30 });

  const [visibleLogs, setVisibleLogs] = useState<typeof attackLogs>([]);

  useEffect(() => {
    let idx = 0;
    const interval = setInterval(() => {
      setVisibleLogs((prev) => {
        const next = [...prev, attackLogs[idx % attackLogs.length]];
        if (next.length > 7) next.shift();
        return next;
      });
      idx++;
    }, 2200);
    return () => clearInterval(interval);
  }, []);

  // Smooth Lenis scrolling
  useEffect(() => {
    const lenis = new Lenis({
      duration: 1.2,
      easing: (t: number) => (t === 1 ? 1 : 1 - Math.pow(2, -10 * t)),
      smoothWheel: true,
      touchMultiplier: 2.5,
      wheelMultiplier: 1.2,
      lerp: 0.12,
    });
    lenisRef.current = lenis;
    function raf(time: number) {
      lenis.raf(time);
      requestAnimationFrame(raf);
    }
    requestAnimationFrame(raf);
    return () => { lenis.destroy(); lenisRef.current = null; };
  }, []);

  const scrollToSection = useCallback((e: React.MouseEvent<HTMLAnchorElement>, id: string) => {
    e.preventDefault();
    const target = document.getElementById(id);
    if (target && lenisRef.current) {
      lenisRef.current.scrollTo(target, { offset: -80, duration: 1.2 });
    }
  }, []);

  // Smooth reveal variant with premium easing
  const smoothReveal = {
    hidden: { opacity: 0, y: 30, filter: "blur(4px)" },
    visible: (i: number) => ({
      opacity: 1,
      y: 0,
      filter: "blur(0px)",
      transition: { delay: i * 0.1, duration: 1, ease: [0.16, 1, 0.3, 1] as [number, number, number, number] },
    }),
  };

  return (
    <>
    {initialLoading && <WireframeLoader onComplete={handleInitialLoadComplete} />}
    {showLoader && <CodeLoader onComplete={handleLoaderComplete} />}
    <div ref={containerRef} className="min-h-screen bg-[#000000] text-white overflow-x-hidden" style={{ fontFamily: "'Space Grotesk', 'Inter', system-ui, sans-serif" }}>
      {/* WebGL Liquid Ether background */}
      <div className="fixed inset-0 pointer-events-none">
        <LiquidEther />
      </div>
      {/* Overlay effects */}
      <div className="fixed inset-0 pointer-events-none">
        <ParticleField />
        <FloatingBlobs />
        <GradualBlur />
      </div>

      {/* Nav */}
      <motion.nav initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }} className="fixed top-0 w-full z-50 border-b border-white/[0.06] bg-black/60 backdrop-blur-2xl">
        <div className="container mx-auto flex items-center justify-between h-16 3xl:h-20 px-4 md:px-8 3xl:px-12 max-w-[1800px]">
          <div className="flex items-center gap-2.5">
            <div className="h-8 w-8 rounded-lg bg-white/10 border border-white/10 flex items-center justify-center">
              <Shield className="h-4 w-4 text-white" />
            </div>
            <span className="text-base font-semibold tracking-tight">IronGuard AI</span>
          </div>
          <div className="hidden md:flex items-center gap-8 text-sm text-white/50">
            <a href="#features" onClick={(e) => scrollToSection(e, 'features')} className="hover:text-white transition-colors duration-500 cursor-pointer">Features</a>
            <a href="#how-it-works" onClick={(e) => scrollToSection(e, 'how-it-works')} className="hover:text-white transition-colors duration-500 cursor-pointer">How It Works</a>
            <a href="#live-monitor" onClick={(e) => scrollToSection(e, 'live-monitor')} className="hover:text-white transition-colors duration-500 cursor-pointer">Live Monitor</a>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={handleGetStarted}>
              <Button variant="ghost" size="sm" className="text-white/50 hover:text-white hover:bg-white/5 transition-all duration-300">Login</Button>
            </button>
            <button onClick={handleGetStarted}>
              <Button size="sm" className="bg-white text-black hover:bg-white/90 rounded-lg px-5 font-medium text-sm transition-all duration-300 hover:shadow-[0_0_20px_rgba(255,255,255,0.15)]">
                Get Started
              </Button>
            </button>
          </div>
        </div>
      </motion.nav>

      {/* Hero */}
      <section className="relative min-h-screen flex items-center justify-center px-4 pt-16 will-change-transform">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[500px] bg-indigo-500/[0.04] rounded-full blur-[160px] pointer-events-none" />

        <motion.div
          style={{ y: heroY, opacity: heroOpacitySmooth }}
          className="container mx-auto text-center relative z-10 max-w-5xl will-change-transform"
        >
           <motion.div
            initial={{ opacity: 0, y: 40, filter: "blur(6px)" }}
            animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
            transition={{ duration: 1.2, ease: [0.16, 1, 0.3, 1] }}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-white/10 bg-white/[0.04] text-white/60 text-sm font-medium mb-10 backdrop-blur-sm"
            >
              <div className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" />
              AI Security Platform
            </motion.div>
            <h1 className="text-6xl md:text-8xl lg:text-9xl font-bold tracking-[-0.04em] leading-[0.9] mb-8">
              <ShinyText
                text="IronGuard AI"
                speed={2}
                delay={0}
                color="#e0e0e0"
                shineColor="#00e5ff"
                spread={120}
                direction="left"
                yoyo={false}
                pauseOnHover={false}
                disabled={false}
              />
            </h1>
            <p className="text-xl md:text-2xl text-white/40 font-light max-w-2xl mx-auto mb-4 tracking-tight">
              <DecryptedText
                text="The Security Firewall for Large Language Models"
                speed={60}
                animateOn="view"
                characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+"
              />
            </p>
            <div className="h-10 mb-12 font-mono text-lg md:text-2xl text-white/60">
              <span className="text-white/30">{'>'} </span>
              <TypingText />
            </div>
            <div className="flex items-center justify-center gap-4">
              <button onClick={handleGetStarted}>
              <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} transition={{ type: "spring", stiffness: 300, damping: 20 }}>
                  <Button size="lg" className="bg-white text-black hover:bg-white/90 px-8 h-12 text-base rounded-xl font-medium group relative overflow-hidden shadow-[0_0_40px_rgba(255,255,255,0.1)] transition-all duration-500 hover:shadow-[0_0_60px_rgba(255,255,255,0.18)]">
                    <span className="relative z-10 flex items-center">
                      Get Started <ArrowRight className="ml-2 h-4 w-4 group-hover:translate-x-1 transition-transform duration-300" />
                    </span>
                  </Button>
                </motion.div>
              </button>
              <button onClick={handleGetStarted}>
              <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} transition={{ type: "spring", stiffness: 300, damping: 20 }}>
                  <Button size="lg" variant="outline" className="border-white/10 bg-white/[0.03] hover:bg-white/[0.06] text-white/70 hover:text-white h-12 px-8 text-base rounded-xl backdrop-blur-sm transition-all duration-500">
                    Explore Dashboard
                  </Button>
                </motion.div>
              </button>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.2, duration: 1 }}
            className="mt-20"
          >
            <ChevronDown className="h-5 w-5 text-white/20 mx-auto animate-bounce" />
          </motion.div>
        </motion.div>
      </section>

      {/* Features */}
      <section id="features" className="py-32 px-4 relative">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-white/[0.01] to-transparent" />
         <div className="container mx-auto max-w-6xl relative z-10">
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-100px" }}
            className="text-center mb-20"
          >
            <motion.p variants={smoothReveal} custom={0} className="text-sm uppercase tracking-[0.2em] text-white/30 mb-4">
              Platform Capabilities
            </motion.p>
             <motion.h2 variants={smoothReveal} custom={1} className="text-4xl md:text-5xl font-bold tracking-tight mb-6 bg-gradient-to-b from-white to-white/60 bg-clip-text text-transparent">
               <DecryptedText text="Enterprise-Grade Security" speed={50} animateOn="view" characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*" />
             </motion.h2>
            <motion.p variants={smoothReveal} custom={2} className="text-white/40 text-lg max-w-xl mx-auto">
              Everything you need to secure your LLM infrastructure
            </motion.p>
          </motion.div>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            {features.map((f, i) => (
              <motion.div
                key={f.title}
                variants={smoothReveal}
                custom={i}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true, margin: "-50px" }}
              >
                <ElectricBorder color="#7df9ff" speed={1} chaos={0.12} borderRadius={20}>
                  <div className="electric-card h-full">
                    <div className="h-10 w-10 rounded-xl bg-white/[0.06] border border-white/[0.08] flex items-center justify-center mb-5">
                      <f.icon className="h-5 w-5 text-white/70" />
                    </div>
                     <h3 className="text-base font-semibold mb-2 text-white/90">{f.title}</h3>
                     <p className="text-white/40 text-sm leading-relaxed">{f.desc}</p>
                  </div>
                </ElectricBorder>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works — Enhanced */}
      <section id="how-it-works" className="py-32 px-4 relative">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-[#0f172a]/70 to-transparent" />
         <div className="container mx-auto max-w-6xl relative z-10">
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-100px" }}
            className="text-center mb-20"
          >
            <motion.p variants={smoothReveal} custom={0} className="text-sm uppercase tracking-[0.2em] text-white/30 mb-4">
              Security Pipeline
            </motion.p>
             <motion.h2 variants={smoothReveal} custom={1} className="text-4xl md:text-5xl font-bold tracking-tight bg-gradient-to-b from-white to-white/60 bg-clip-text text-transparent">
               <DecryptedText text="How It Works" speed={50} animateOn="view" characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*" />
             </motion.h2>
          </motion.div>
          <div className="mt-12">
            <GatewayVisualizer />
          </div>
        </div>
      </section>

      {/* Live Attack Monitor — Enhanced */}
       <section id="live-monitor" className="py-32 px-4 relative">
         <div className="container mx-auto max-w-6xl relative z-10">
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-100px" }}
            className="text-center mb-16"
          >
            <motion.p variants={smoothReveal} custom={0} className="text-sm uppercase tracking-[0.2em] text-white/30 mb-4">
              Live Preview
            </motion.p>
            <motion.h2 variants={smoothReveal} custom={1} className="text-4xl md:text-5xl font-bold tracking-tight mb-6 bg-gradient-to-b from-white to-white/60 bg-clip-text text-transparent">
               <DecryptedText text="Real-Time Attack Monitor" speed={50} animateOn="view" characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*" />
             </motion.h2>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 30, filter: "blur(4px)" }}
            whileInView={{ opacity: 1, y: 0, filter: "blur(0px)" }}
            viewport={{ once: true }}
            transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
            className="rounded-2xl border border-white/[0.06] bg-black/80 backdrop-blur-xl overflow-hidden shadow-[0_0_60px_rgba(120,130,255,0.04)] relative"
          >

            {/* Terminal header */}
            <div className="flex items-center gap-2 px-5 py-3 border-b border-white/[0.06] bg-white/[0.02]">
              <div className="flex gap-1.5">
                <div className="h-2.5 w-2.5 rounded-full bg-red-500/60" />
                <div className="h-2.5 w-2.5 rounded-full bg-yellow-500/60" />
                <div className="h-2.5 w-2.5 rounded-full bg-green-500/60" />
              </div>
              <div className="flex-1 flex justify-center">
                <span className="text-xs text-white/30 font-mono">ironguard://threat-monitor — active scanning</span>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5">
                  <div className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse shadow-[0_0_6px_rgba(74,222,128,0.6)]" />
                  <span className="text-[10px] text-green-400/70 font-mono">CONNECTED</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="h-1.5 w-1.5 rounded-full bg-red-500 animate-pulse shadow-[0_0_6px_rgba(239,68,68,0.6)]" />
                  <span className="text-[10px] text-red-400/70 font-mono">LIVE</span>
                </div>
              </div>
            </div>

            {/* Stats bar */}
            <div className="flex items-center gap-6 px-5 py-2 border-b border-white/[0.04] bg-white/[0.01] font-mono text-[10px]">
              <span className="text-white/20">THREATS: <span className="text-red-400/70">23</span></span>
              <span className="text-white/20">BLOCKED: <span className="text-orange-400/70">18</span></span>
              <span className="text-white/20">SAFE: <span className="text-green-400/70">4,271</span></span>
              <span className="text-white/20 ml-auto">LATENCY: <span className="text-cyan-400/70">12ms</span></span>
            </div>

            {/* Log entries */}
            <div className="p-4 font-mono text-sm space-y-0.5 min-h-[280px] relative">
              {visibleLogs.map((log, i) => (
                <TerminalLogLine key={`${log.time}-${i}-${log.user}`} log={log} />
              ))}
              {visibleLogs.length === 0 && (
                <div className="text-white/20 text-xs animate-pulse">Initializing threat monitoring...</div>
              )}
            </div>

            {/* Bottom bar */}
            <div className="flex items-center px-5 py-2 border-t border-white/[0.04] bg-white/[0.01] font-mono text-[10px] text-white/15">
              <span>$ ironguard --watch --verbose</span>
              <span className="animate-pulse ml-1">▊</span>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Dashboard Preview */}
       <section className="py-32 px-4 relative">
         <div className="container mx-auto max-w-6xl relative z-10">
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-100px" }}
            className="text-center mb-16"
          >
            <motion.p variants={smoothReveal} custom={0} className="text-sm uppercase tracking-[0.2em] text-white/30 mb-4">
              Dashboard Overview
            </motion.p>
            <motion.h2 variants={smoothReveal} custom={1} className="text-4xl md:text-5xl font-bold tracking-tight bg-gradient-to-b from-white to-white/60 bg-clip-text text-transparent">
               <DecryptedText text="Security at a Glance" speed={50} animateOn="view" characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*" />
             </motion.h2>
          </motion.div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {dashboardStats.map((stat, i) => (
              <motion.div
                key={stat.label}
                variants={smoothReveal}
                custom={i}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true }}
              >
                <ElectricBorder color="#7df9ff" speed={0.8} chaos={0.08} borderRadius={20}>
                  <div className="electric-card">
                    <p className="text-xs uppercase tracking-wider text-white/30 mb-3">{stat.label}</p>
                    <p className="text-3xl font-bold text-white/90 mb-2 tracking-tight">{stat.value}</p>
                    <p className="text-xs text-white/30">{stat.change}</p>
                  </div>
                </ElectricBorder>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Built for Scale */}
      <section className="py-32 px-4 relative overflow-hidden">
        <div className="absolute inset-0 bg-[#0A0A0A]" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[500px] bg-indigo-500/[0.04] rounded-full blur-[180px] pointer-events-none" />

        <div className="container mx-auto max-w-5xl relative z-10">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-80px" }}
            transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] as [number, number, number, number] }}
            className="text-center mb-16"
          >
            <p className="text-sm uppercase tracking-[0.2em] text-white/30 mb-6">Built for Scale</p>
            <h2 className="text-4xl md:text-6xl font-bold tracking-tight mb-6 bg-gradient-to-b from-white via-white/80 to-white/30 bg-clip-text text-transparent">
               <DecryptedText text="Protecting Millions of AI Interactions" speed={50} animateOn="view" characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*" />
             </h2>
            <p className="text-lg text-white/30 max-w-xl mx-auto">
              From startups to enterprise, IronGuard AI scales with your infrastructure to ensure every prompt is secure.
            </p>
          </motion.div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-5 md:gap-6">
            {scaleStats.map((stat, i) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-50px" }}
                transition={{ delay: i * 0.12, duration: 0.8, ease: [0.16, 1, 0.3, 1] as [number, number, number, number] }}
              >
                <div className="text-center p-4 sm:p-5 md:p-6 rounded-2xl bg-white/[0.03] border border-white/[0.06] hover:bg-white/[0.05] hover:border-white/[0.1] transition-all duration-500 group h-full">
                  <div className="h-10 w-10 rounded-lg bg-white/[0.05] border border-white/[0.08] flex items-center justify-center mx-auto mb-3 md:mb-4 group-hover:bg-white/[0.08] transition-colors duration-500">
                    <stat.icon className="h-4 w-4 text-white/50 group-hover:text-white/70 transition-colors duration-300" />
                  </div>
                  <p className="text-lg sm:text-xl md:text-2xl font-bold text-white/90 tracking-tight mb-1">
                    <AnimatedCounter target={stat.target} suffix={stat.suffix} duration={2.5} />
                  </p>
                  <p className="text-[10px] md:text-xs text-white/30 uppercase tracking-wider">{stat.label}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA — Enhanced */}
      <section className="py-32 px-4 relative">
        <div className="absolute inset-0 bg-gradient-to-b from-[#0A0A0A] to-black" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-indigo-500/[0.04] rounded-full blur-[150px]" />
        <div className="container mx-auto max-w-3xl relative z-10 text-center">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
          >
            <h2 className="text-4xl md:text-6xl font-bold tracking-tight mb-6 bg-gradient-to-b from-white to-white/60 bg-clip-text text-transparent">
               <DecryptedText text="Secure Your AI Infrastructure Today" speed={50} animateOn="view" characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*" />
             </h2>
            <p className="text-lg text-white/30 mb-10 max-w-lg mx-auto leading-relaxed">
              Start protecting your LLM systems in minutes. No complex setup required.
            </p>
            <Link to="/login">
              <motion.div
                whileHover={{ scale: 1.04 }}
                whileTap={{ scale: 0.97 }}
                transition={{ type: "spring", stiffness: 300, damping: 20 }}
                className="inline-block"
              >
                <Button size="lg" className="bg-white text-black hover:bg-white/90 px-10 h-14 text-base rounded-xl font-medium group relative overflow-hidden shadow-[0_0_50px_rgba(255,255,255,0.08)] transition-shadow duration-500 hover:shadow-[0_0_80px_rgba(255,255,255,0.15)]">
                  <span className="relative z-10 flex items-center">
                    Start Protecting Your AI <ArrowRight className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform duration-300" />
                  </span>
                </Button>
              </motion.div>
            </Link>
          </motion.div>
        </div>
      </section>

      {/* Footer — Full */}
       <footer className="border-t border-white/[0.06] py-16 px-4 bg-black relative">
         <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[400px] h-px bg-gradient-to-r from-transparent via-white/[0.15] to-transparent" />
         <div className="container mx-auto max-w-6xl">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-12 mb-16">
            {/* Brand */}
            <div className="col-span-2 md:col-span-1">
              <div className="flex items-center gap-2.5 mb-4">
                <div className="h-7 w-7 rounded-lg bg-white/10 border border-white/10 flex items-center justify-center">
                  <Shield className="h-3.5 w-3.5 text-white" />
                </div>
                <span className="font-semibold tracking-tight">IronGuard AI</span>
              </div>
              <p className="text-xs text-white/25 leading-relaxed max-w-[200px]">
                AI-powered prompt security for modern LLM infrastructure.
              </p>
            </div>

            {/* Product */}
            <div>
              <p className="text-xs font-semibold text-white/50 uppercase tracking-wider mb-4">Product</p>
              <ul className="space-y-2.5">
                <li><a href="#features" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">Features</a></li>
                <li><a href="#monitor" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">Real Time Monitoring</a></li>
                <li><a href="#" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">Prompt Protection</a></li>
                <li><a href="#" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">API Integration</a></li>
              </ul>
            </div>

            {/* Resources */}
            <div>
              <p className="text-xs font-semibold text-white/50 uppercase tracking-wider mb-4">Resources</p>
              <ul className="space-y-2.5">
                <li><a href="#" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">Documentation</a></li>
                <li><a href="#" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">GitHub</a></li>
                <li><a href="#" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">API Reference</a></li>
                <li><a href="#" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">Security Guide</a></li>
              </ul>
            </div>

            {/* Company */}
            <div>
              <p className="text-xs font-semibold text-white/50 uppercase tracking-wider mb-4">Company</p>
              <ul className="space-y-2.5">
                <li><a href="#" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">About</a></li>
                <li><a href="#" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">Contact</a></li>
                <li><a href="#" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">Privacy Policy</a></li>
                <li><a href="#" className="text-sm text-white/25 hover:text-white/60 transition-colors duration-300">Terms</a></li>
              </ul>
            </div>
          </div>

          <div className="h-px bg-white/[0.06] mb-8" />
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <p className="text-xs text-white/20">© 2026 IronGuard AI. All rights reserved.</p>
            <p className="text-xs text-white/15">Protecting AI systems from prompt attacks.</p>
          </div>
        </div>
      </footer>
    </div>
    </>
  );
};

export default Index;
