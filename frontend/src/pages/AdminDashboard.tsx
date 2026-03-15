import { useState, useEffect, useCallback } from "react";
import CodeLoader from "@/components/ui/CodeLoader";
import { api, AttackFrequencyData, TopThreatsData, RiskDistributionData } from "@/lib/api";
import { useUser, useClerk } from "@clerk/clerk-react";
import { Shield, BarChart3, Users, AlertTriangle, Activity, Settings, FileText, Monitor, LayoutDashboard, TrendingUp, Lock, Eye, Zap, Bell, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { motion, AnimatePresence } from "framer-motion";
import { AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, RadarChart, PolarGrid, PolarAngleAxis, Radar } from "recharts";
import AuroraBackground from "@/components/ui/AuroraBackground";
import FloatingBlobs from "@/components/ui/FloatingBlobs";
import LiquidEther from "@/components/ui/LiquidEther";
import { toast } from "@/hooks/use-toast";

// ─── Glass card wrapper ────────────────────────────────────
const GlassCard = ({ children, className = "" }: { children: React.ReactNode; className?: string }) => (
  <div className={`rounded-2xl border border-white/[0.06] bg-black/40 backdrop-blur-xl ${className}`}>
    {children}
  </div>
);

const tabs = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "analytics", label: "Threat Analytics", icon: BarChart3 },
  { id: "live-monitor", label: "Live Monitor", icon: Monitor },
  { id: "security-logs", label: "Security Logs", icon: FileText },
  { id: "settings", label: "Settings", icon: Settings },
];

const stats = [
  { icon: Users, label: "Total Users", value: "2,847", change: "+12%", changeType: "up" },
  { icon: BarChart3, label: "Prompts Analyzed", value: "48,392", change: "+8%", changeType: "up" },
  { icon: AlertTriangle, label: "Threats Blocked", value: "1,284", change: "+23%", changeType: "up" },
  { icon: Activity, label: "Threat Level", value: "Medium", change: "Stable", changeType: "neutral" },
];

const recentActivity = [
  { time: "12:41", user: "User21", status: "SAFE PROMPT", type: "safe" },
  { time: "12:42", user: "User14", status: "PROMPT INJECTION DETECTED", type: "danger" },
  { time: "12:43", user: "User09", status: "BLOCKED", type: "danger" },
  { time: "12:44", user: "User05", status: "DATA EXTRACTION ATTEMPT", type: "warning" },
  { time: "12:45", user: "User33", status: "SAFE PROMPT", type: "safe" },
];

// Chart data
const threatTimelineData = [
  { time: "00:00", threats: 12, blocked: 11, safe: 420 },
  { time: "04:00", threats: 8, blocked: 8, safe: 310 },
  { time: "08:00", threats: 24, blocked: 23, safe: 580 },
  { time: "12:00", threats: 45, blocked: 43, safe: 720 },
  { time: "16:00", threats: 38, blocked: 37, safe: 650 },
  { time: "20:00", threats: 22, blocked: 21, safe: 490 },
  { time: "Now", threats: 31, blocked: 30, safe: 560 },
];

const threatTypesPie = [
  { name: "Injection", value: 482, color: "#ef4444" },
  { name: "Extraction", value: 234, color: "#f97316" },
  { name: "Jailbreak", value: 312, color: "#eab308" },
  { name: "Manipulation", value: 156, color: "#8b5cf6" },
  { name: "Obfuscation", value: 98, color: "#06b6d4" },
];

const weeklyData = [
  { day: "Mon", threats: 142, blocked: 140 },
  { day: "Tue", threats: 198, blocked: 196 },
  { day: "Wed", threats: 167, blocked: 165 },
  { day: "Thu", threats: 221, blocked: 218 },
  { day: "Fri", threats: 189, blocked: 187 },
  { day: "Sat", threats: 94, blocked: 94 },
  { day: "Sun", threats: 78, blocked: 78 },
];

const responseTimeData = [
  { time: "00:00", latency: 14 },
  { time: "04:00", latency: 11 },
  { time: "08:00", latency: 18 },
  { time: "12:00", latency: 22 },
  { time: "16:00", latency: 16 },
  { time: "20:00", latency: 13 },
  { time: "Now", latency: 12 },
];

const radarData = [
  { category: "Injection", score: 92 },
  { category: "Extraction", score: 88 },
  { category: "Jailbreak", score: 95 },
  { category: "Manipulation", score: 78 },
  { category: "Obfuscation", score: 85 },
  { category: "Override", score: 91 },
];

const threatAnalyticsData = [
  { category: "Prompt Injection", count: 482, severity: "CRITICAL", trend: "+15%" },
  { category: "Data Extraction", count: 234, severity: "HIGH", trend: "+8%" },
  { category: "Role Manipulation", count: 156, severity: "HIGH", trend: "+32%" },
  { category: "Jailbreak Attempts", count: 312, severity: "CRITICAL", trend: "+5%" },
  { category: "Obfuscated Inputs", count: 98, severity: "MEDIUM", trend: "-2%" },
  { category: "System Override", count: 67, severity: "CRITICAL", trend: "+18%" },
];

const liveMonitorLogs = [
  { time: "12:41:03", ip: "192.168.1.47", user: "session_a8f2", status: "SAFE PROMPT — Standard query processed", type: "safe", severity: "LOW" },
  { time: "12:41:18", ip: "10.0.3.112", user: "session_c4d1", status: "⚠ PROMPT INJECTION ATTEMPT — Escape sequence detected", type: "danger", severity: "CRITICAL" },
  { time: "12:41:32", ip: "172.16.0.89", user: "session_f7a9", status: "BLOCKED — Recursive jailbreak pattern", type: "danger", severity: "HIGH" },
  { time: "12:41:45", ip: "10.0.7.203", user: "session_b2e5", status: "⚠ DATA EXTRACTION — Payload blocked at layer 3", type: "warning", severity: "HIGH" },
  { time: "12:42:01", ip: "192.168.4.15", user: "session_d9c3", status: "SAFE PROMPT — Verified clean input", type: "safe", severity: "LOW" },
  { time: "12:42:14", ip: "10.0.1.67", user: "session_e1b8", status: "⚠ DAN-style bypass attempt neutralized", type: "danger", severity: "CRITICAL" },
  { time: "12:42:28", ip: "172.16.2.44", user: "session_a3f6", status: "SAFE PROMPT — Standard query processed", type: "safe", severity: "LOW" },
  { time: "12:42:41", ip: "10.0.9.156", user: "session_g5h2", status: "BLOCKED — Obfuscated instruction injection", type: "danger", severity: "HIGH" },
];

const securityLogsData = [
  { id: "LOG-001", timestamp: "2026-03-08 12:41:03", event: "Prompt scan completed", level: "INFO", source: "Scanner v3.2" },
  { id: "LOG-002", timestamp: "2026-03-08 12:41:18", event: "Injection attempt detected & blocked", level: "CRITICAL", source: "Firewall" },
  { id: "LOG-003", timestamp: "2026-03-08 12:41:32", event: "User session flagged for review", level: "WARNING", source: "Behavior Engine" },
  { id: "LOG-004", timestamp: "2026-03-08 12:41:45", event: "Data extraction payload intercepted", level: "HIGH", source: "DLP Module" },
  { id: "LOG-005", timestamp: "2026-03-08 12:42:01", event: "Threat model updated successfully", level: "INFO", source: "ML Pipeline" },
  { id: "LOG-006", timestamp: "2026-03-08 12:42:14", event: "DAN bypass neutralized at edge", level: "CRITICAL", source: "Firewall" },
  { id: "LOG-007", timestamp: "2026-03-08 12:42:28", event: "Scheduled scan completed — 0 threats", level: "INFO", source: "Scanner v3.2" },
  { id: "LOG-008", timestamp: "2026-03-08 12:42:41", event: "New threat signature added to database", level: "INFO", source: "Threat Intel" },
];

const fadeUp = {
  hidden: { opacity: 0, y: 30 },
  visible: (i: number) => ({
    opacity: 1, y: 0,
    transition: { delay: i * 0.1, duration: 0.5 },
  }),
};

const tabContent = {
  hidden: { opacity: 0, y: 15, filter: "blur(3px)" },
  visible: { opacity: 1, y: 0, filter: "blur(0px)", transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] as [number, number, number, number] } },
  exit: { opacity: 0, y: -10, filter: "blur(3px)", transition: { duration: 0.2 } },
};

const chartTooltipStyle = {
  contentStyle: { background: "rgba(0,0,0,0.85)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "12px", fontSize: "12px", color: "#fff", backdropFilter: "blur(12px)" },
  itemStyle: { color: "#ccc" },
  labelStyle: { color: "#666" },
};

// ─── Dashboard Tab ─────────────────────────────────────────
const DashboardTab = ({ frequencyData, riskDistribution, topThreats }: { 
  frequencyData: AttackFrequencyData | null, 
  riskDistribution: RiskDistributionData | null,
  topThreats: TopThreatsData | null
}) => {
  const threatTimelineData = frequencyData ? frequencyData.labels.map((label, idx) => ({
    time: label,
    threats: frequencyData.datasets[0].data[idx] + frequencyData.datasets[1].data[idx],
    blocked: frequencyData.datasets[0].data[idx],
    safe: 500 + Math.floor(Math.random() * 200) // Mock safe traffic
  })) : [];

  const threatTypesPie = topThreats ? Object.entries(topThreats).map(([name, value], i) => ({
    name,
    value,
    color: ["#ef4444", "#f97316", "#eab308", "#8b5cf6", "#06b6d4"][i % 5]
  })) : [];

  return (
    <div className="space-y-6">
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat, i) => (
          <motion.div key={stat.label} variants={fadeUp} custom={i} initial="hidden" animate="visible">
            <GlassCard className="p-5">
              <div className="flex items-center gap-3 mb-3">
                <div className="h-9 w-9 rounded-xl bg-white/[0.05] border border-white/[0.06] flex items-center justify-center">
                  <stat.icon className="h-4 w-4 text-white/60" />
                </div>
                <span className="text-[10px] uppercase tracking-wider text-white/25">{stat.label}</span>
              </div>
              <p className="text-3xl font-bold text-white/90 tracking-tight">{stat.value}</p>
              <p className={`text-xs mt-1 ${stat.changeType === "up" ? "text-green-400/70" : "text-white/25"}`}>{stat.change}</p>
            </GlassCard>
          </motion.div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <GlassCard className="p-5 lg:col-span-2">
          <h2 className="text-sm font-semibold text-white/70 mb-4">Threat Activity Timeline</h2>
          {threatTimelineData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={threatTimelineData}>
                <defs>
                  <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="safeGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22c55e" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#22c55e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="time" stroke="rgba(255,255,255,0.15)" tick={{ fontSize: 10 }} />
                <YAxis stroke="rgba(255,255,255,0.15)" tick={{ fontSize: 10 }} />
                <Tooltip {...chartTooltipStyle} />
                <Area type="monotone" dataKey="safe" stroke="#22c55e" fill="url(#safeGrad)" strokeWidth={1.5} />
                <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#threatGrad)" strokeWidth={2} />
                <Area type="monotone" dataKey="blocked" stroke="#f97316" fill="none" strokeWidth={1.5} strokeDasharray="4 4" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[220px] flex items-center justify-center text-white/20 text-xs">Loading analytics...</div>
          )}
        </GlassCard>

        <GlassCard className="p-5">
          <h2 className="text-sm font-semibold text-white/70 mb-4">Threat Distribution</h2>
          {threatTypesPie.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={threatTypesPie} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value" stroke="none">
                  {threatTypesPie.map((entry, index) => (
                    <Cell key={index} fill={entry.color} fillOpacity={0.7} />
                  ))}
                </Pie>
                <Tooltip {...chartTooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[220px] flex items-center justify-center text-white/20 text-xs">Loading analysis...</div>
          )}
        </GlassCard>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <GlassCard className="p-5">
          <h2 className="text-sm font-semibold text-white/70 mb-4">Recent Activity</h2>
          <div className="space-y-1.5 font-mono text-sm">
            {recentActivity.map((log, i) => (
              <div key={i} className="flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-white/[0.03] transition-colors">
                <span className="text-white/15">[{log.time}]</span>
                <span className="text-white/40">{log.user}</span>
                <span className="text-white/10">→</span>
                <span className={log.type === "safe" ? "text-green-400/80" : log.type === "warning" ? "text-yellow-400/80" : "text-red-400/90"}>
                  {log.status}
                </span>
              </div>
            ))}
          </div>
        </GlassCard>

        <GlassCard className="p-5">
          <h2 className="text-sm font-semibold text-white/70 mb-4">System Status</h2>
          <div className="space-y-3">
            {[
              { label: "Firewall", status: "Active", icon: Shield },
              { label: "ML Pipeline", status: "Running", icon: Zap },
              { label: "Threat Intel", status: "Updated", icon: Eye },
              { label: "DLP Module", status: "Active", icon: Lock },
            ].map((sys, i) => (
              <div key={i} className="flex items-center justify-between py-2.5 px-3 rounded-xl bg-white/[0.02] border border-white/[0.04]">
                <div className="flex items-center gap-3">
                  <sys.icon className="h-4 w-4 text-white/30" />
                  <span className="text-sm text-white/50">{sys.label}</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" />
                  <span className="text-xs text-green-400/60 font-mono">{sys.status}</span>
                </div>
              </div>
            ))}
          </div>
        </GlassCard>
      </div>
    </div>
  );
};

// ─── Threat Analytics Tab ──────────────────────────────────
const ThreatAnalyticsTab = () => (
  <div>
    <div className="grid sm:grid-cols-3 gap-4 mb-6">
      {[
        { label: "Total Threats", value: "1,349", icon: AlertTriangle, color: "text-red-400/80" },
        { label: "Blocked Rate", value: "99.7%", icon: Shield, color: "text-green-400/80" },
        { label: "Avg Response", value: "12ms", icon: Zap, color: "text-cyan-400/80" },
      ].map((s, i) => (
        <motion.div key={s.label} variants={fadeUp} custom={i} initial="hidden" animate="visible">
          <GlassCard className="p-5">
            <div className="flex items-center gap-3 mb-3">
              <s.icon className={`h-5 w-5 ${s.color}`} />
              <span className="text-[10px] uppercase tracking-wider text-white/25">{s.label}</span>
            </div>
            <p className="text-3xl font-bold text-white/90 tracking-tight">{s.value}</p>
          </GlassCard>
        </motion.div>
      ))}
    </div>

    <div className="grid lg:grid-cols-2 gap-4 mb-6">
      {/* Weekly bar chart */}
      <GlassCard className="p-5">
        <h2 className="text-sm font-semibold text-white/70 mb-4">Weekly Threats vs Blocked</h2>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={weeklyData} barGap={2}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
            <XAxis dataKey="day" stroke="rgba(255,255,255,0.15)" tick={{ fontSize: 10 }} />
            <YAxis stroke="rgba(255,255,255,0.15)" tick={{ fontSize: 10 }} />
            <Tooltip {...chartTooltipStyle} />
            <Bar dataKey="threats" fill="#ef4444" fillOpacity={0.5} radius={[4, 4, 0, 0]} />
            <Bar dataKey="blocked" fill="#22c55e" fillOpacity={0.4} radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </GlassCard>

      {/* Response time line chart */}
      <GlassCard className="p-5">
        <h2 className="text-sm font-semibold text-white/70 mb-4">Response Latency (ms)</h2>
        <ResponsiveContainer width="100%" height={240}>
          <LineChart data={responseTimeData}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
            <XAxis dataKey="time" stroke="rgba(255,255,255,0.15)" tick={{ fontSize: 10 }} />
            <YAxis stroke="rgba(255,255,255,0.15)" tick={{ fontSize: 10 }} />
            <Tooltip {...chartTooltipStyle} />
            <Line type="monotone" dataKey="latency" stroke="#06b6d4" strokeWidth={2} dot={{ fill: "#06b6d4", r: 3, strokeWidth: 0 }} />
          </LineChart>
        </ResponsiveContainer>
      </GlassCard>
    </div>

    <div className="grid lg:grid-cols-3 gap-4">
      {/* Radar chart */}
      <GlassCard className="p-5">
        <h2 className="text-sm font-semibold text-white/70 mb-4">Defense Coverage</h2>
        <ResponsiveContainer width="100%" height={240}>
          <RadarChart data={radarData}>
            <PolarGrid stroke="rgba(255,255,255,0.08)" />
            <PolarAngleAxis dataKey="category" tick={{ fontSize: 9, fill: "rgba(255,255,255,0.35)" }} />
            <Radar dataKey="score" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.15} strokeWidth={2} />
          </RadarChart>
        </ResponsiveContainer>
      </GlassCard>

      {/* Threat breakdown table */}
      <GlassCard className="p-5 lg:col-span-2">
        <h2 className="text-sm font-semibold text-white/70 mb-4">Threat Breakdown</h2>
        <div className="space-y-2">
          {threatAnalyticsData.map((t, i) => (
            <div key={i} className="flex items-center gap-4 py-2.5 px-4 rounded-xl bg-white/[0.02] border border-white/[0.03] hover:bg-white/[0.04] transition-colors">
              <div className="flex-1">
                <p className="text-sm font-medium text-white/70">{t.category}</p>
              </div>
              {/* Mini bar */}
              <div className="w-24 h-1.5 rounded-full bg-white/[0.05] overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${(t.count / 500) * 100}%`,
                    backgroundColor: t.severity === "CRITICAL" ? "#ef4444" : t.severity === "HIGH" ? "#f97316" : "#eab308",
                    opacity: 0.6,
                  }}
                />
              </div>
              <span className="text-sm font-mono text-white/50 w-12 text-right">{t.count}</span>
              <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-medium ${
                t.severity === "CRITICAL" ? "text-red-400 bg-red-400/10" :
                t.severity === "HIGH" ? "text-orange-400 bg-orange-400/10" :
                "text-yellow-400 bg-yellow-400/10"
              }`}>{t.severity}</span>
              <span className={`text-xs font-mono w-12 text-right ${t.trend.startsWith("+") ? "text-red-400/60" : "text-green-400/60"}`}>{t.trend}</span>
              <TrendingUp className={`h-3.5 w-3.5 ${t.trend.startsWith("+") ? "text-red-400/40" : "text-green-400/40 rotate-180"}`} />
            </div>
          ))}
        </div>
      </GlassCard>
    </div>
  </div>
);

// ─── Live Monitor Tab ──────────────────────────────────────
const LiveMonitorTab = () => (
  <div>
    <GlassCard className="overflow-hidden">
      <div className="flex items-center gap-2 px-5 py-3 border-b border-white/[0.05] bg-white/[0.01]">
        <div className="flex gap-1.5">
          <div className="h-2.5 w-2.5 rounded-full bg-red-500/50" />
          <div className="h-2.5 w-2.5 rounded-full bg-yellow-500/50" />
          <div className="h-2.5 w-2.5 rounded-full bg-green-500/50" />
        </div>
        <div className="flex-1 flex justify-center">
          <span className="text-xs text-white/25 font-mono">ironguard://admin-monitor — live feed</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse shadow-[0_0_6px_rgba(74,222,128,0.6)]" />
            <span className="text-[10px] text-green-400/60 font-mono">CONNECTED</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-1.5 w-1.5 rounded-full bg-red-500 animate-pulse shadow-[0_0_6px_rgba(239,68,68,0.6)]" />
            <span className="text-[10px] text-red-400/60 font-mono">LIVE</span>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-6 px-5 py-2 border-b border-white/[0.03] bg-white/[0.005] font-mono text-[10px]">
        <span className="text-white/15">THREATS: <span className="text-red-400/60">23</span></span>
        <span className="text-white/15">BLOCKED: <span className="text-orange-400/60">18</span></span>
        <span className="text-white/15">SAFE: <span className="text-green-400/60">4,271</span></span>
        <span className="text-white/15 ml-auto">LATENCY: <span className="text-cyan-400/60">12ms</span></span>
      </div>

      <div className="p-4 font-mono text-sm space-y-1 min-h-[350px]">
        {liveMonitorLogs.map((log, i) => {
          const severityColor = log.severity === "CRITICAL" ? "text-red-500" : log.severity === "HIGH" ? "text-orange-400" : "text-green-400";
          return (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.08, duration: 0.4 }}
              className="flex items-start gap-2 py-2 px-3 rounded-lg hover:bg-white/[0.02] transition-colors"
            >
              <span className="text-white/10 shrink-0 text-xs">[{log.time}]</span>
              <span className="text-white/20 shrink-0 text-xs">{log.ip}</span>
              <span className="text-cyan-400/40 shrink-0 text-xs">{log.user}</span>
              <span className="text-white/[0.06]">│</span>
              <span className={`text-xs flex-1 ${
                log.type === "safe" ? "text-green-400/70" :
                log.type === "warning" ? "text-yellow-400/70" :
                "text-red-400/80"
              }`}>{log.status}</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 ${severityColor} font-medium`}
                style={{ backgroundColor: log.severity === "CRITICAL" ? "rgba(239,68,68,0.08)" : log.severity === "HIGH" ? "rgba(251,146,60,0.08)" : "rgba(74,222,128,0.08)" }}>
                {log.severity}
              </span>
              {(log.type === "danger" || log.type === "warning") && (
                <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse shrink-0 mt-1 shadow-[0_0_8px_rgba(239,68,68,0.6)]" />
              )}
            </motion.div>
          );
        })}
      </div>

      <div className="flex items-center px-5 py-2 border-t border-white/[0.03] bg-white/[0.005] font-mono text-[10px] text-white/10">
        <span>$ ironguard --watch --verbose --admin</span>
        <span className="animate-pulse ml-1">▊</span>
      </div>
    </GlassCard>
  </div>
);

// ─── Security Logs Tab ─────────────────────────────────────
const SecurityLogsTab = () => (
  <div>
    <div className="grid sm:grid-cols-2 gap-4 mb-6">
      <GlassCard className="p-5">
        <div className="flex items-center gap-3 mb-2">
          <Bell className="h-4 w-4 text-yellow-400/60" />
          <span className="text-sm font-medium text-white/60">Active Alerts</span>
        </div>
        <p className="text-2xl font-bold text-white/90">7</p>
        <p className="text-xs text-white/25 mt-1">3 critical, 4 warning</p>
      </GlassCard>
      <GlassCard className="p-5">
        <div className="flex items-center gap-3 mb-2">
          <FileText className="h-4 w-4 text-cyan-400/60" />
          <span className="text-sm font-medium text-white/60">Total Logs Today</span>
        </div>
        <p className="text-2xl font-bold text-white/90">12,847</p>
        <p className="text-xs text-white/25 mt-1">+1,284 from yesterday</p>
      </GlassCard>
    </div>

    <GlassCard className="p-5">
      <h2 className="text-sm font-semibold text-white/70 mb-4">Security Event Log</h2>
      <div className="space-y-2">
        {securityLogsData.map((log, i) => (
          <motion.div
            key={log.id}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05, duration: 0.3 }}
            className="flex items-center gap-4 py-2.5 px-4 rounded-xl bg-white/[0.015] border border-white/[0.03] hover:bg-white/[0.03] transition-colors font-mono text-xs"
          >
            <span className="text-white/15 shrink-0 w-16">{log.id}</span>
            <span className="text-white/25 shrink-0 w-40">{log.timestamp}</span>
            <span className="text-white/50 flex-1">{log.event}</span>
            <span className={`px-2 py-0.5 rounded font-medium shrink-0 ${
              log.level === "CRITICAL" ? "text-red-400 bg-red-400/8" :
              log.level === "HIGH" ? "text-orange-400 bg-orange-400/8" :
              log.level === "WARNING" ? "text-yellow-400 bg-yellow-400/8" :
              "text-white/30 bg-white/[0.03]"
            }`}>{log.level}</span>
            <span className="text-white/20 shrink-0 w-28 text-right">{log.source}</span>
          </motion.div>
        ))}
      </div>
    </GlassCard>
  </div>
);

// ─── Settings Tab ──────────────────────────────────────────
const SettingsTab = () => (
  <div className="grid lg:grid-cols-2 gap-4">
    <GlassCard className="p-5">
      <h2 className="text-sm font-semibold text-white/70 mb-4">Security Settings</h2>
      <div className="space-y-3">
        {[
          { label: "Prompt Injection Detection", desc: "Block injection attempts automatically", enabled: true },
          { label: "Data Extraction Prevention", desc: "Prevent sensitive data leaks via prompts", enabled: true },
          { label: "Jailbreak Protection", desc: "Detect and block jailbreak patterns", enabled: true },
          { label: "Role Manipulation Guard", desc: "Prevent system prompt overrides", enabled: false },
        ].map((setting, i) => (
          <div key={i} className="flex items-center justify-between py-3 px-4 rounded-xl bg-white/[0.015] border border-white/[0.03]">
            <div>
              <p className="text-sm font-medium text-white/60">{setting.label}</p>
              <p className="text-xs text-white/25 mt-0.5">{setting.desc}</p>
            </div>
            <div className={`h-5 w-9 rounded-full flex items-center px-0.5 transition-colors ${setting.enabled ? "bg-green-500/20" : "bg-white/[0.06]"}`}>
              <div className={`h-4 w-4 rounded-full transition-all ${setting.enabled ? "bg-green-400/80 translate-x-4" : "bg-white/20 translate-x-0"}`} />
            </div>
          </div>
        ))}
      </div>
    </GlassCard>

    <GlassCard className="p-5">
      <h2 className="text-sm font-semibold text-white/70 mb-4">Notifications & Alerts</h2>
      <div className="space-y-3">
        {[
          { label: "Email Alerts", desc: "Get notified for critical threats", enabled: true },
          { label: "Slack Integration", desc: "Post alerts to your Slack channel", enabled: false },
          { label: "Webhook Notifications", desc: "Send events to custom endpoints", enabled: true },
          { label: "Daily Digest", desc: "Receive a daily security summary", enabled: true },
        ].map((setting, i) => (
          <div key={i} className="flex items-center justify-between py-3 px-4 rounded-xl bg-white/[0.015] border border-white/[0.03]">
            <div>
              <p className="text-sm font-medium text-white/60">{setting.label}</p>
              <p className="text-xs text-white/25 mt-0.5">{setting.desc}</p>
            </div>
            <div className={`h-5 w-9 rounded-full flex items-center px-0.5 transition-colors ${setting.enabled ? "bg-green-500/20" : "bg-white/[0.06]"}`}>
              <div className={`h-4 w-4 rounded-full transition-all ${setting.enabled ? "bg-green-400/80 translate-x-4" : "bg-white/20 translate-x-0"}`} />
            </div>
          </div>
        ))}
      </div>
    </GlassCard>

    <GlassCard className="p-5 lg:col-span-2">
      <h2 className="text-sm font-semibold text-white/70 mb-4">API Configuration</h2>
      <div className="space-y-3">
        <div className="py-3 px-4 rounded-xl bg-white/[0.015] border border-white/[0.03]">
          <p className="text-[10px] text-white/25 mb-2 uppercase tracking-wider">API Key</p>
          <div className="flex items-center gap-3">
            <code className="text-sm text-white/40 font-mono flex-1 bg-white/[0.02] px-3 py-2 rounded-lg">ig_live_sk_••••••••••••••••••••</code>
            <Button size="sm" variant="ghost" className="text-white/30 hover:text-white text-xs">Reveal</Button>
            <Button size="sm" variant="ghost" className="text-white/30 hover:text-white text-xs">Rotate</Button>
          </div>
        </div>
        <div className="py-3 px-4 rounded-xl bg-white/[0.015] border border-white/[0.03]">
          <p className="text-[10px] text-white/25 mb-2 uppercase tracking-wider">Webhook URL</p>
          <code className="text-sm text-white/40 font-mono bg-white/[0.02] px-3 py-2 rounded-lg block">https://api.ironguard.ai/webhooks/v1/events</code>
        </div>
      </div>
    </GlassCard>
  </div>
);

const AdminDashboard = () => {
  const { user } = useUser();
  const { signOut } = useClerk();
  const [activeTab, setActiveTab] = useState("dashboard");
  const [loading, setLoading] = useState(true);
  const [analyticsData, setAnalyticsData] = useState<{
    frequency: AttackFrequencyData | null;
    threats: TopThreatsData | null;
    risk: RiskDistributionData | null;
  }>({ frequency: null, threats: null, risk: null });

  const fetchAnalytics = useCallback(async () => {
    try {
      const [freq, threats, risk] = await Promise.all([
        api.getAttackFrequency(),
        api.getTopThreats(),
        api.getRiskDistribution()
      ]);
      setAnalyticsData({ frequency: freq, threats, risk });
    } catch (error: any) {
      console.error("Failed to fetch analytics:", error);
      toast({
        title: "Analytics Error",
        description: "Could not fetch latest security data from IronGuard Engine.",
        variant: "destructive",
      });
    }
  }, []);

  useEffect(() => {
    fetchAnalytics();
    const interval = setInterval(fetchAnalytics, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, [fetchAnalytics]);

  // Block browser back navigation
  useEffect(() => {
    window.history.pushState(null, "", window.location.href);
    const handlePopState = () => {
      window.history.pushState(null, "", window.location.href);
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const handleLoadComplete = useCallback(() => setLoading(false), []);

  if (loading) return <CodeLoader onComplete={handleLoadComplete} />;

  return (
    <div className="min-h-screen bg-[#050508] text-white relative" style={{ fontFamily: "'Space Grotesk','Inter',system-ui,sans-serif" }}>
      <div className="fixed inset-0 pointer-events-none">
        <AuroraBackground />
        <LiquidEther />
        <FloatingBlobs />
      </div>

      <nav className="sticky top-0 z-50 border-b border-white/[0.04] bg-black/50 backdrop-blur-2xl">
        <div className="container mx-auto flex items-center justify-between h-16 px-4 md:px-8">
          <div className="flex items-center gap-2.5">
            <div className="h-8 w-8 rounded-lg bg-white/[0.06] border border-white/[0.06] flex items-center justify-center">
              <Shield className="h-4 w-4 text-white/70" />
            </div>
            <span className="text-base font-semibold tracking-tight text-white/90">IronGuard AI — Admin</span>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-white/35">{user?.primaryEmailAddress?.emailAddress}</span>
            <Button size="sm" variant="ghost" className="text-red-400 hover:text-red-300 hover:bg-red-500/10" onClick={() => signOut()}>
              Sign Out
            </Button>
          </div>
        </div>
      </nav>

      <div className="container mx-auto px-4 py-10 relative z-10">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
          <div className="flex items-end justify-between mb-8">
            <div>
              <h1 className="text-4xl font-bold mb-2 bg-gradient-to-b from-white to-white/50 bg-clip-text text-transparent">
                Admin Dashboard
              </h1>
              <p className="text-white/30">Welcome back, {user?.firstName || "Admin"}.</p>
            </div>
            <Button size="sm" variant="ghost" className="text-[10px] text-white/20 hover:text-white" onClick={fetchAnalytics}>
              <Activity className="h-3 w-3 mr-2" /> REFRESH LIVE DATA
            </Button>
          </div>
        </motion.div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 mb-8 p-1 rounded-xl bg-black/30 backdrop-blur-lg border border-white/[0.04] w-fit">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300 ${
                activeTab === tab.id
                  ? "bg-white/[0.06] text-white/90 border border-white/[0.08]"
                  : "text-white/30 hover:text-white/50 hover:bg-white/[0.02] border border-transparent"
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <AnimatePresence mode="wait">
          <motion.div key={activeTab} variants={tabContent} initial="hidden" animate="visible" exit="exit">
            {activeTab === "dashboard" && (
              <DashboardTab 
                frequencyData={analyticsData.frequency} 
                riskDistribution={analyticsData.risk}
                topThreats={analyticsData.threats}
              />
            )}
            {activeTab === "analytics" && <ThreatAnalyticsTab />}
            {activeTab === "live-monitor" && <LiveMonitorTab />}
            {activeTab === "security-logs" && <SecurityLogsTab />}
            {activeTab === "settings" && <SettingsTab />}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
};

export default AdminDashboard;
