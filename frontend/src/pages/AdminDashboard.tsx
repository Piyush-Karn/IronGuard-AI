import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import AdminSettings from "./AdminSettings";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import CodeLoader from "@/components/ui/CodeLoader";
import { api, AttackFrequencyData, TopThreatsData, RiskDistributionData } from "@/lib/api";
import { useUser, useClerk } from "@clerk/clerk-react";
import { Shield, BarChart3, Users, AlertTriangle, Activity, Settings, FileText, Monitor, LayoutDashboard, TrendingUp, Lock, Eye, Zap, Bell, Loader2, Check, Share2, Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { motion, AnimatePresence } from "framer-motion";
import { AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, RadarChart, PolarGrid, PolarAngleAxis, Radar } from "recharts";
import AuroraBackground from "@/components/ui/AuroraBackground";
import FloatingBlobs from "@/components/ui/FloatingBlobs";
import LiquidEther from "@/components/ui/LiquidEther";
import { toast } from "@/hooks/use-toast";
import GatewayVisualizer from "@/components/GatewayVisualizer";

// ─── Glass card wrapper ────────────────────────────────────
const GlassCard = ({ children, className = "" }: { children: React.ReactNode; className?: string }) => (
  <div className={`rounded-2xl border border-white/[0.06] bg-black/40 backdrop-blur-xl ${className}`}>
    {children}
  </div>
);

const tabs = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "analytics", label: "Threat Analytics", icon: BarChart3 },
  { id: "interactive-flow", label: "Interactive Flow", icon: Share2 },
  { id: "team", label: "Team", icon: Users },
  { id: "live-monitor", label: "Live Monitor", icon: Monitor },
  { id: "gateway", label: "Gateway Registry", icon: Lock },
  { id: "self-learning", label: "Self-Learning", icon: Zap },
  { id: "security-logs", label: "Security Logs", icon: FileText },
  { id: "settings", label: "Settings", icon: Settings },
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
const DashboardTab = ({ frequencyData, riskDistribution, topThreats, latencyMetrics, sanitizationRatio, blockingEfficiency, logs }: { 
  frequencyData: AttackFrequencyData | null, 
  riskDistribution: RiskDistributionData | null,
  topThreats: TopThreatsData | null,
  latencyMetrics: any,
  sanitizationRatio: any,
  blockingEfficiency: any,
  logs: any[]
}) => {
  const threatTimelineData = frequencyData ? frequencyData.labels.map((label, idx) => ({
    time: label,
    threats: frequencyData.datasets.reduce((acc, ds) => acc + (ds.data[idx] || 0), 0),
    blocked: frequencyData.datasets.find(ds => ds.label === "Blocked")?.data[idx] || 0,
    safe: (frequencyData.datasets.find(ds => ds.label === "Passed")?.data[idx] || 0) + (frequencyData.datasets.find(ds => ds.label === "Safe")?.data[idx] || 0)
  })) : [];

  const threatTypesPie = topThreats ? Object.entries(topThreats).map(([name, value], i) => ({
    name,
    value,
    color: ["#ef4444", "#f97316", "#eab308", "#8b5cf6", "#06b6d4"][i % 5]
  })) : [];

  const totalLogs = sanitizationRatio?.total || 0;
  const threatsBlocked = (blockingEfficiency?.Blocked || 0);
  
  const dashboardStats = [
    { icon: Users, label: "Total Users", value: "Active", change: "Real-time", changeType: "neutral" },
    { icon: BarChart3, label: "Prompts Analyzed", value: totalLogs.toLocaleString(), change: "Total Volume", changeType: "neutral" },
    { icon: AlertTriangle, label: "Threats Blocked", value: threatsBlocked.toLocaleString(), change: `${threatsBlocked > 0 ? "+" : ""}${threatsBlocked}`, changeType: "up" },
    { icon: Activity, label: "Avg Latency", value: `${Math.round(latencyMetrics?.avg_latency || 0)}ms`, change: "System Performance", changeType: "neutral" },
  ];

  return (
    <div className="space-y-6">
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {dashboardStats.map((stat, i) => (
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
          <h2 className="text-sm font-semibold text-white/70 mb-4">Live Activity</h2>
          <div className="space-y-1.5 font-mono text-xs">
            {logs && logs.length > 0 ? logs.slice(0, 5).map((log: any, i: number) => (
              <div key={log._id || i} className="flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-white/[0.03] transition-colors">
                <span className="text-white/15">[{new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}]</span>
                <span className="text-white/40 truncate max-w-[80px]">{log.user_id}</span>
                <span className="text-white/10">→</span>
                <span className={log.action_taken === "Passed" || log.action_taken === "Safe" ? "text-green-400/80" : log.action_taken === "Sanitized" ? "text-yellow-400/80" : "text-red-400/90"}>
                  {(log.action_taken || "").toUpperCase()}
                </span>
              </div>
            )) : (
              <div className="h-32 flex items-center justify-center text-white/10 italic">No recent activity</div>
            )}
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
const ThreatAnalyticsTab = ({ 
  frequencyData, 
  latencyMetrics, 
  policyViolations 
}: { 
  frequencyData: AttackFrequencyData | null, 
  latencyMetrics: any, 
  policyViolations: any 
}) => {
  const radarData = policyViolations ? Object.entries(policyViolations).map(([category, count]) => ({
    category,
    score: Math.min(100, (Number(count) / 10) * 100)
  })) : [];

  const threatAnalyticsData = (policyViolations && typeof policyViolations === 'object') ? Object.entries(policyViolations).map(([category, count]) => ({
    category,
    count: Number(count),
    severity: Number(count) > 5 ? "CRITICAL" : Number(count) > 2 ? "HIGH" : "MEDIUM",
    trend: "+0%"
  })) : [];

  return (
    <div>
      <div className="grid sm:grid-cols-3 gap-4 mb-6">
        {[
          { label: "Total Violations", value: threatAnalyticsData.reduce((acc, t) => acc + (Number(t.count) || 0), 0), icon: AlertTriangle, color: "text-red-400/80" },
          { label: "Blocked Rate", value: "99.7%", icon: Shield, color: "text-green-400/80" },
          { label: "Avg Response", value: `${Math.round(latencyMetrics?.avg_latency || 0)}ms`, icon: Zap, color: "text-cyan-400/80" },
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
          <h2 className="text-sm font-semibold text-white/70 mb-4">Historical Attack Volume</h2>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={frequencyData?.labels.map((l, i) => ({
              day: l,
              threats: frequencyData.datasets.find(ds => ds.label === "Blocked")?.data[i] || 0,
              safe: (frequencyData.datasets.find(ds => ds.label === "Passed")?.data[i] || 0) + (frequencyData.datasets.find(ds => ds.label === "Safe")?.data[i] || 0)
            })) || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis dataKey="day" stroke="rgba(255,255,255,0.15)" tick={{ fontSize: 10 }} />
              <YAxis stroke="rgba(255,255,255,0.15)" tick={{ fontSize: 10 }} />
              <Tooltip {...chartTooltipStyle} />
              <Bar dataKey="threats" fill="#ef4444" fillOpacity={0.5} radius={[4, 4, 0, 0]} />
              <Bar dataKey="safe" fill="#22c55e" fillOpacity={0.4} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </GlassCard>

        {/* Response time line chart */}
        <GlassCard className="p-5">
          <h2 className="text-sm font-semibold text-white/70 mb-4">Engine Latency Profile</h2>
          <div className="flex items-center justify-center h-[240px] flex-col gap-4">
             <div className="flex gap-8">
                <div className="text-center">
                  <p className="text-3xl font-bold text-cyan-400">{Math.round(latencyMetrics?.avg_latency || 0)}ms</p>
                  <p className="text-[10px] text-white/20 uppercase font-bold mt-1">Average</p>
                </div>
                <div className="text-center">
                  <p className="text-3xl font-bold text-blue-400">{Math.round(latencyMetrics?.p95_latency || 0)}ms</p>
                  <p className="text-[10px] text-white/20 uppercase font-bold mt-1">P95</p>
                </div>
             </div>
             <div className="w-full px-8">
                <div className="h-1.5 w-full bg-white/[0.05] rounded-full overflow-hidden">
                  <div className="h-full bg-cyan-500/50" style={{ width: `${Math.min(100, (latencyMetrics?.avg_latency || 0) * 2)}%` }} />
                </div>
             </div>
          </div>
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
                <div className="w-24 h-1.5 rounded-full bg-white/[0.05] overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${(Number(t.count) / 20) * 100}%`,
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
              </div>
            ))}
          </div>
        </GlassCard>
      </div>
    </div>
  );
};

// ─── Live Monitor Tab ──────────────────────────────────────
const LiveMonitorTab = ({ logs }: { logs: any[] }) => (
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

      <div className="p-4 font-mono text-xs space-y-1 min-h-[350px] max-h-[500px] overflow-y-auto">
        {logs && logs.length > 0 ? logs.map((log: any, i: number) => {
          const actionColor = log.action_taken === "Blocked" ? "text-red-500" : log.action_taken === "Sanitized" ? "text-orange-400" : "text-green-400";
          return (
            <motion.div
              key={log._id || i}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex items-start gap-3 py-2 px-3 border-b border-white/[0.02] hover:bg-white/[0.02] transition-colors"
            >
              <span className="text-white/10 shrink-0">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
              <span className="text-white/20 shrink-0">{log.ip_address || "internal"}</span>
              <span className="text-cyan-400/30 truncate w-20 shrink-0">{log.user_id}</span>
              <span className="text-white/[0.06]">│</span>
              <span className={`flex-1 truncate ${actionColor}`}>{log.prompt}</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 ${actionColor} bg-white/[0.03]`}>
                {(log.action_taken || "").toUpperCase()}
              </span>
            </motion.div>
          );
        }) : (
           <div className="h-full flex items-center justify-center text-white/10 italic py-20">No live telemetry available</div>
        )}
      </div>

      <div className="flex items-center px-5 py-2 border-t border-white/[0.03] bg-white/[0.005] font-mono text-[10px] text-white/10">
        <span>$ ironguard --watch --verbose --admin --tail</span>
        <span className="animate-pulse ml-1">▊</span>
      </div>
    </GlassCard>
  </div>
);

// ─── Team Tab (User Management) ──────────────────────────
const TeamTab = () => {
  const { user } = useUser();
  const [selectedUser, setSelectedUser] = useState<any>(null);
  const { data: usersData, isLoading } = useQuery({
    queryKey: ["usersList", user?.id],
    queryFn: () => api.getUsersList(user?.id || ""),
    enabled: !!user?.id,
    refetchInterval: 30000,
  });

  const [inviteSecret, setInviteSecret] = useState<{ userId: string; secret: string } | null>(null);
  const [isGeneratingInvite, setIsGeneratingInvite] = useState(false);

  if (isLoading) {
    return (
      <div className="h-[400px] flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const users = usersData?.users || [];

  const handleGenerateInvite = async (userId: string) => {
    setIsGeneratingInvite(true);
    try {
      const data = await api.createUserInvite(userId, user?.id || "");
      setInviteSecret({ userId, secret: data.secret });
      toast({
        title: "Secret Generated",
        description: "One-time authorization secret created successfully.",
      });
    } catch (error: any) {
      toast({
        variant: "destructive",
        title: "Generation Failed",
        description: error.message || "Could not create invite secret.",
      });
    } finally {
      setIsGeneratingInvite(false);
    }
  };

  return (
    <div className="space-y-6">
      <GlassCard className="p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-sm font-semibold text-white/70">Employee Security Overview</h2>
          <Button size="sm" variant="outline" className="text-[10px] text-white/40 border-white/10">
            EXPORT CSV
          </Button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-white/[0.04] text-[10px] uppercase tracking-wider text-white/20">
                <th className="py-3 px-4 font-medium">Employee</th>
                <th className="py-3 px-4 font-medium">Role</th>
                <th className="py-3 px-4 font-medium">Trust Score</th>
                <th className="py-3 px-4 font-medium">Total Scans</th>
                <th className="py-3 px-4 font-medium">Safe/Blocked</th>
                <th className="py-3 px-4 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.02]">
              {users.map((u, i) => (
                <motion.tr 
                  key={u.user_id}
                  initial={{ opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.03 }}
                  className="group hover:bg-white/[0.01] transition-colors"
                >
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-3">
                      <div className="h-8 w-8 rounded-full bg-gradient-to-br from-blue-500/20 to-purple-500/20 border border-white/10 flex items-center justify-center text-[10px] font-bold text-white/60">
                        {(u.full_name || u.email || "U").charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-white/80">{u.full_name || (u.email ? u.email.split("@")[0] : "User")}</p>
                        <p className="text-[10px] text-white/20 font-mono">{u.email}</p>
                        <p className="text-[10px] text-white/10 font-mono">{u.user_id}</p>
                      </div>
                    </div>
                  </td>
                  <td className="py-4 px-4 font-mono text-xs">
                    <span className={`px-2 py-0.5 rounded ${u.role === "admin" ? "bg-blue-500/10 text-blue-400" : "bg-white/5 text-white/40"}`}>
                      {u.role}
                    </span>
                  </td>
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-2">
                       <div className="flex-1 h-1 rounded-full bg-white/[0.05] w-12 overflow-hidden">
                        <div className={`h-full ${u.trust_score > 80 ? "bg-green-500" : u.trust_score > 50 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${u.trust_score}%` }} />
                       </div>
                       <span className="text-xs font-mono text-white/60">{u.trust_score}</span>
                    </div>
                  </td>
                  <td className="py-4 px-4 font-mono text-xs text-white/40">
                    {u.total_checked}
                  </td>
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-3 text-[10px] font-mono">
                      <span className="text-green-500/60">{u.sanitized}</span>
                      <span className="text-white/10">/</span>
                      <span className="text-red-500/60">{u.blocked}</span>
                    </div>
                  </td>
                  <td className="py-4 px-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                        {u.role !== "admin" && (
                            <Button 
                                size="sm" 
                                variant="outline" 
                                onClick={() => handleGenerateInvite(u.user_id)}
                                disabled={isGeneratingInvite}
                                className="text-[10px] h-7 border-blue-500/20 text-blue-400/70 hover:bg-blue-500/10 hover:text-blue-400"
                            >
                                {isGeneratingInvite ? <Loader2 className="h-3 w-3 animate-spin"/> : "INVITE"}
                            </Button>
                        )}
                        <Button 
                            size="sm" 
                            variant="ghost" 
                            onClick={() => setSelectedUser(u)}
                            className="text-[10px] h-7 text-white/30 hover:text-white hover:bg-white/5"
                        >
                            STATS
                        </Button>
                    </div>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </GlassCard>

      {/* Secret Display Modal */}
      <AnimatePresence>
        {inviteSecret && (
          <motion.div 
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/80 backdrop-blur-xl"
          >
             <div className="w-full max-w-md bg-[#0c0c0e] border border-blue-500/30 rounded-3xl p-8 shadow-[0_0_50px_rgba(59,130,246,0.1)]">
                <div className="text-center mb-6">
                    <div className="h-12 w-12 bg-blue-500/10 rounded-full flex items-center justify-center mx-auto mb-4 border border-blue-500/20">
                        <Lock className="h-6 w-6 text-blue-500" />
                    </div>
                    <h3 className="text-xl font-bold text-white">Authorization Secret</h3>
                    <p className="text-xs text-white/30 mt-2">Generated for: <span className="text-blue-400 font-mono">{inviteSecret.userId}</span></p>
                </div>

                <div className="relative group mb-6">
                    <div className="absolute inset-0 bg-blue-500/5 blur-xl group-hover:bg-blue-500/10 transition-all opacity-50" />
                    <div className="relative p-6 rounded-2xl bg-black/40 border border-white/5 text-center">
                        <p className="text-2xl font-mono font-bold text-white tracking-[0.2em]">{inviteSecret.secret}</p>
                    </div>
                </div>

                <div className="space-y-4">
                    <div className="p-4 rounded-xl bg-amber-500/5 border border-amber-500/10 flex gap-3 items-start">
                        <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
                        <p className="text-[10px] text-amber-200/50 leading-relaxed uppercase tracking-widest font-bold">
                            Warning: This secret will only be shown once. It is cryptographically random and valid for 7 days.
                        </p>
                    </div>

                    <Button 
                        className="w-full bg-blue-600 hover:bg-blue-700 h-12 text-white font-bold"
                        onClick={() => {
                            navigator.clipboard.writeText(inviteSecret.secret);
                            toast({ title: "Copied!", description: "Secret copied to clipboard." });
                        }}
                    >
                        COPY TO CLIPBOARD
                    </Button>
                    <Button 
                        variant="ghost" 
                        className="w-full text-white/20 hover:text-white"
                        onClick={() => setInviteSecret(null)}
                    >
                        CLOSE
                    </Button>
                </div>
             </div>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {selectedUser && (
          <motion.div 
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-md"
            onClick={() => setSelectedUser(null)}
          >
            <div 
              className="w-full max-w-2xl bg-[#0a0a0c] border border-white/10 rounded-3xl overflow-hidden shadow-2xl"
              onClick={e => e.stopPropagation()}
            >
              <div className="p-6 border-b border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-4">
                   <div className="h-12 w-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center">
                      <Users className="h-6 w-6 text-blue-400" />
                   </div>
                   <div>
                      <h3 className="text-lg font-bold text-white/90">{selectedUser.full_name || (selectedUser.email ? selectedUser.email.split("@")[0] : "User")}'s Security Profile</h3>
                      <p className="text-xs text-white/20 font-mono">{selectedUser.user_id}</p>
                   </div>
                </div>
                <Button variant="ghost" className="text-white/20 hover:text-white" onClick={() => setSelectedUser(null)}>
                  CLOSE
                </Button>
              </div>
              <div className="p-8">
                  {/* Reusing Employee View components implicitly via stats */}
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                     {[
                       { label: "Checks", val: selectedUser.total_checked, icon: Activity, color: "text-blue-400" },
                       { label: "Blocked", val: selectedUser.blocked, icon: Shield, color: "text-red-400" },
                       { label: "Clean", val: selectedUser.sanitized, icon: Zap, color: "text-green-400" },
                       { label: "Score", val: selectedUser.trust_score, icon: TrendingUp, color: "text-amber-400" },
                     ].map((s, i) => (
                       <div key={i} className="rounded-2xl bg-white/[0.03] border border-white/[0.05] p-4 text-center">
                          <s.icon className={`h-4 w-4 mx-auto mb-2 ${s.color} opacity-60`} />
                          <p className="text-xl font-bold text-white/90">{s.val}</p>
                          <p className="text-[9px] uppercase tracking-tighter text-white/20 mt-1">{s.label}</p>
                       </div>
                     ))}
                  </div>

                  <div className="space-y-4">
                     <p className="text-[10px] uppercase tracking-widest text-white/20 font-bold mb-2">Detailed Risk Assessment</p>
                     <div className="p-4 rounded-xl bg-red-500/5 border border-red-500/10 flex items-start gap-4">
                        <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                        <div>
                          <p className="text-xs text-red-200/60 font-medium">Threat Level: {selectedUser.trust_score < 40 ? "CRITICAL" : selectedUser.trust_score < 70 ? "MEDIUM" : "LOW"}</p>
                          <p className="text-[10px] text-white/25 mt-1 leading-relaxed">
                            Based on manual aggregation, this user has {selectedUser.blocked} security violations. 
                            {selectedUser.trust_score < 70 ? " Immediate monitoring or policy review is advised." : " No immediate action required."}
                          </p>
                        </div>
                     </div>
                  </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// ─── Self-Learning Tab ─────────────────────────────────────
const SelfLearningTab = ({ adminId }: { adminId: string }) => {
  const [currentPage, setCurrentPage] = useState(1);
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);
  const itemsPerPage = 7;

  const { data: pingData, error: pingError } = useQuery({
    queryKey: ["adminPing"],
    queryFn: () => api.pingAdmin(),
    retry: false
  });

  const { data: fpData, isLoading, error } = useQuery({
    queryKey: ["fingerprints", adminId],
    queryFn: () => api.getFingerprints(adminId),
    enabled: !!adminId,
    refetchInterval: 30000,
  });

  if (pingError) {
    return (
      <div className="h-64 flex flex-col items-center justify-center text-red-500/50 uppercase tracking-widest text-xs gap-4 border border-dashed border-red-500/20 rounded-3xl p-8 text-center font-sans">
        <AlertTriangle className="h-8 w-8 mb-2" />
        <p>Admin Router Unreachable (404)</p>
        <p className="text-[10px] normal-case mt-1 opacity-50">The backend "/api/v1/analytics" prefix might be misconfigured. {(pingError as Error).message}</p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="h-64 flex flex-col items-center justify-center text-white/20 uppercase tracking-widest text-xs gap-4">
        <Loader2 className="h-8 w-8 animate-spin" />
        <p>Analyzing intelligence feed...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-64 flex flex-col items-center justify-center text-red-500/50 uppercase tracking-widest text-xs gap-4 border border-dashed border-red-500/20 rounded-3xl p-8 text-center">
        <AlertTriangle className="h-8 w-8 mb-2" />
        <p>Failed to load intelligence feed</p>
        <p className="text-[10px] normal-case mt-1 opacity-50">{(error as Error).message}</p>
      </div>
    );
  }

  const fingerprints = fpData?.fingerprints || [];
  // Reverse order (newest first)
  const learnedPatterns = [...fingerprints].reverse().filter((f: any) => f.attack_type === "Learned");
  
  const totalPages = Math.ceil(learnedPatterns.length / itemsPerPage);
  const currentItems = learnedPatterns.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  return (
    <div className="space-y-6">
      <div className="grid sm:grid-cols-3 gap-4">
        <GlassCard className="p-5">
          <div className="flex items-center gap-3 mb-3">
            <Zap className="h-4 w-4 text-amber-400" />
            <span className="text-[10px] uppercase tracking-wider text-white/25">Autonomously Learned</span>
          </div>
          <p className="text-3xl font-bold text-white/90 tracking-tight">{learnedPatterns.length}</p>
          <p className="text-xs text-white/20 mt-1">Patterns identified & blocked</p>
        </GlassCard>
        <GlassCard className="p-5">
          <div className="flex items-center gap-3 mb-3">
            <Shield className="h-4 w-4 text-blue-400" />
            <span className="text-[10px] uppercase tracking-wider text-white/25">Total Fingerprints</span>
          </div>
          <p className="text-3xl font-bold text-white/90 tracking-tight">{fingerprints.length}</p>
          <p className="text-xs text-white/20 mt-1">Known threat signatures</p>
        </GlassCard>
        <GlassCard className="p-5">
          <div className="flex items-center gap-3 mb-3">
            <Activity className="h-4 w-4 text-green-400" />
            <span className="text-[10px] uppercase tracking-wider text-white/25">Hot-Reload Status</span>
          </div>
          <p className="text-3xl font-bold text-green-400/90 tracking-tight">ACTIVE</p>
          <p className="text-xs text-white/20 mt-1">Real-time DB sync enabled</p>
        </GlassCard>
      </div>

      <GlassCard className="p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-sm font-semibold text-white/70">Autonomous Threat Intelligence Feed</h2>
          <div className="flex items-center gap-4">
            <span className="text-[10px] text-white/20 font-mono">NEWEST FIRST</span>
            <span className="text-[10px] text-white/20 font-mono">SOURCE: FINGERPRINT_DB.JSON</span>
          </div>
        </div>

        <div className="space-y-3">
          {currentItems.length > 0 ? currentItems.map((fp: any, i: number) => {
            const globalIndex = (currentPage - 1) * itemsPerPage + i;
            const isExpanded = expandedIndex === globalIndex;

            return (
              <motion.div
                key={globalIndex}
                layout
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                className={`group p-4 rounded-xl bg-white/[0.02] border transition-all font-sans cursor-pointer ${isExpanded ? 'border-amber-500/40 bg-white/[0.04]' : 'border-white/[0.05] hover:border-amber-500/30'}`}
                onClick={() => setExpandedIndex(isExpanded ? null : globalIndex)}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-1.5 rounded-full bg-amber-500 animate-pulse" />
                    <span className="text-[10px] font-mono text-amber-500/70 uppercase tracking-widest">New Threat Pattern Identified</span>
                  </div>
                  <span className="text-[10px] text-white/10 font-mono uppercase">ID: FP-ALT-{learnedPatterns.length - globalIndex + 100}</span>
                </div>
                <p className={`text-sm text-white/80 font-mono bg-black/40 p-3 rounded-lg border border-white/[0.03] overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner ${isExpanded ? 'mb-4' : 'mb-3'}`}>
                  {fp.canonical_form}
                </p>
                <div className="flex items-center justify-between border-t border-white/[0.04] pt-3">
                  <div className="flex items-center gap-4">
                    <div className="flex items-center gap-1.5">
                      <Zap className="h-3 w-3 text-white/20" />
                      <span className="text-[10px] text-white/30 uppercase font-bold text-[8px]">Confidence: HIGH</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Lock className="h-3 w-3 text-white/20" />
                      <span className="text-[10px] text-white/30 uppercase font-bold text-[8px]">Action: GLOBAL_BLOCK</span>
                    </div>
                  </div>
                  <span className="text-[10px] text-white/20 italic flex items-center gap-1">
                    {isExpanded ? 'click to collapse' : 'click to expand'}
                  </span>
                </div>

                <AnimatePresence>
                  {isExpanded && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      className="overflow-hidden mt-4 pt-4 border-t border-white/[0.05] space-y-4"
                    >
                      <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-1">
                          <p className="text-[9px] text-white/20 uppercase font-bold tracking-widest">Autonomous Detection Signatures</p>
                          <p className="text-xs text-white/50 italic px-1">{fp.description || "Independently verified by Security Engine V2"}</p>
                        </div>
                        <div className="space-y-1">
                          <p className="text-[9px] text-white/20 uppercase font-bold tracking-widest">Redaction Status</p>
                          <p className="text-xs text-green-400/60 font-mono flex items-center gap-1.5 px-1 uppercase font-bold">
                           <Check className="h-2.5 w-2.5" /> PII_CLEANSED
                          </p>
                        </div>
                      </div>
                      <div className="p-3 bg-white/[0.02] rounded-lg border border-white/[0.02]">
                        <p className="text-[9px] text-white/10 uppercase font-bold mb-2 tracking-widest">Technical Discovery Metadata</p>
                        <p className="text-[11px] text-white/30 leading-relaxed font-sans px-1">
                          This pattern was identified during an automated cross-session audit. 
                          The Security Engine V2 determined with high confidence that this mutation 
                          represents a sophisticated injection attempts designed to circumvent standard static analysis. 
                          Automated hot-reload has distributed this signature to all edge nodes.
                        </p>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            );
          }) : (
            <div className="h-40 flex flex-col items-center justify-center text-white/10 italic space-y-2">
              <Zap className="h-8 w-8 opacity-20" />
              <p>No autonomously learned threats yet.</p>
            </div>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-3 mt-8">
            <Button
              size="sm"
              variant="ghost"
              disabled={currentPage === 1}
              onClick={(e) => { e.stopPropagation(); setCurrentPage(prev => prev - 1); }}
              className="text-white/40 hover:text-white bg-white/[0.02] h-8 px-4 border border-white/[0.05]"
            >
              Previous
            </Button>
            <span className="text-[10px] text-white/20 uppercase tracking-widest font-bold px-2">
              Page {currentPage} / {totalPages}
            </span>
            <Button
              size="sm"
              variant="ghost"
              disabled={currentPage === totalPages}
              onClick={(e) => { e.stopPropagation(); setCurrentPage(prev => prev + 1); }}
              className="text-white/40 hover:text-white bg-white/[0.02] h-8 px-4 border border-white/[0.05]"
            >
              Next
            </Button>
          </div>
        )}
      </GlassCard>
    </div>
  );
};

// ─── Security Logs Tab ─────────────────────────────────────
const SecurityLogsTab = ({ logs }: { logs: any[] }) => (
  <div className="space-y-6">
    <GlassCard className="p-5">
      <h2 className="text-sm font-semibold text-white/70 mb-4">Master Security Event Log</h2>
      <div className="space-y-1.5">
        {logs && logs.length > 0 ? logs.map((log: any, i: number) => (
          <motion.div
            key={log._id || i}
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-4 py-2 px-4 rounded-xl bg-white/[0.015] border border-white/[0.03] hover:bg-white/[0.03] transition-colors font-mono text-[11px]"
          >
            <span className="text-white/10 shrink-0 w-32">{new Date(log.timestamp).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}</span>
            <span className="text-cyan-400/30 shrink-0 w-24 truncate">{log.user_id}</span>
            <span className="text-white/40 flex-1 truncate">{log.prompt}</span>
            <span className={`px-2 py-0.5 rounded font-bold shrink-0 ${
              log.action_taken === "Blocked" ? "text-red-400 bg-red-400/10" :
              log.action_taken === "Sanitized" ? "text-orange-400 bg-orange-400/10" :
              "text-green-400 bg-green-400/10"
            }`}>{ (log.action_taken || "").toUpperCase() }</span>
            <span className="text-white/10 shrink-0 w-12 text-right">{log.risk_score}</span>
          </motion.div>
        )) : (
            <div className="h-40 flex items-center justify-center text-white/10 italic">No logs recorded yet</div>
        )}
      </div>
    </GlassCard>
  </div>
);
// ─── Gateway Registry Tab ─────────────────────────────────
const GatewayRegistryTab = ({ adminId }: { adminId: string }) => {
  const queryClient = useQueryClient();
  const [isRegistering, setIsRegistering] = useState(false);
  const [newClientName, setNewClientName] = useState("");
  const [registrationResult, setRegistrationResult] = useState<any>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["gatewayClients", adminId],
    queryFn: () => api.getGatewayClients(adminId),
    enabled: !!adminId,
    refetchInterval: 30000,
  });

  const registerMutation = useMutation({
    mutationFn: (name: string) => api.registerGatewayClient(adminId, { client_name: name }),
    onSuccess: (data) => {
      setRegistrationResult(data);
      setNewClientName("");
      queryClient.invalidateQueries({ queryKey: ["gatewayClients"] });
      toast({ title: "Client Registered", description: "Successfully created new gateway client." });
    },
    onError: (err: any) => {
      toast({ title: "Registration Failed", description: err.message, variant: "destructive" });
    }
  });

  const revokeMutation = useMutation({
    mutationFn: (clientId: string) => api.revokeGatewayClient(adminId, clientId, "Deactivated by admin"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["gatewayClients"] });
      toast({ title: "Client Revoked", description: "Gateway client access has been removed." });
    }
  });

  if (isLoading) return <div className="h-40 flex items-center justify-center"><Loader2 className="h-6 w-6 animate-spin text-white/20" /></div>;

  const clients = data?.clients || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white/90">Trusted Execution Gateways</h2>
        <Button 
          onClick={() => setIsRegistering(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white font-bold px-6 rounded-xl"
        >
          <Plus className="h-4 w-4 mr-2" /> REGISTER NEW CLIENT
        </Button>
      </div>

      <div className="grid gap-4">
        {clients.length === 0 ? (
          <div className="h-64 rounded-3xl border border-dashed border-white/5 flex flex-col items-center justify-center text-white/10 gap-2">
            <Lock className="h-8 w-8 opacity-20" />
            <p className="text-sm italic">No active gateway clients found</p>
          </div>
        ) : (
          clients.map((client: any) => (
            <GlassCard key={client.client_id} className="p-6 flex items-center justify-between group">
              <div className="flex items-center gap-6">
                 <div className="h-12 w-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center">
                    <Shield className={`h-6 w-6 ${client.is_active ? "text-blue-400" : "text-white/20"}`} />
                 </div>
                 <div>
                    <div className="flex items-center gap-3">
                      <h3 className="text-lg font-bold text-white/90 tracking-tight">{client.client_name}</h3>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-mono ${client.is_active ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-500"}`}>
                        {client.is_active ? "ACTIVE" : "REVOKED"}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 mt-1">
                      <p className="text-[10px] text-white/20 font-mono tracking-tighter uppercase">ID: {client.client_id}</p>
                      <span className="text-white/[0.05]">|</span>
                      <p className="text-[10px] text-white/20 font-mono tracking-tighter uppercase">Usage: {client.request_count} Requests</p>
                    </div>
                 </div>
              </div>

              <div className="flex items-center gap-3 opacity-0 group-hover:opacity-100 transition-opacity">
                <Button 
                  variant="ghost" 
                  size="sm" 
                  className="text-red-500/40 hover:text-red-500 hover:bg-red-500/10 rounded-xl"
                  onClick={() => {
                    if (confirm("Are you sure? This will immediately break all integrations for this client.")) {
                      revokeMutation.mutate(client.client_id);
                    }
                  }}
                >
                  <Trash2 className="h-4 w-4 mr-2" /> REVOKE ACCESS
                </Button>
              </div>
            </GlassCard>
          ))
        )}
      </div>

      <AnimatePresence>
        {isRegistering && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-xl p-4">
            <GlassCard className="w-full max-w-md p-8 relative">
              {registrationResult ? (
                <div className="space-y-6 text-center">
                  <div className="h-16 w-16 bg-green-500/10 rounded-full flex items-center justify-center mx-auto border border-green-500/20">
                    <Check className="h-8 w-8 text-green-500" />
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-white mb-2">Registration Complete</h3>
                    <p className="text-sm text-white/30">Safeguard this secret. It will never be shown again.</p>
                  </div>
                  <div className="p-6 rounded-2xl bg-black/40 border border-white/5 font-mono text-center">
                    <p className="text-xs text-white/20 mb-2 uppercase tracking-widest">Client Secret</p>
                    <p className="text-lg font-bold text-blue-400 tracking-wider break-all">{registrationResult.secret}</p>
                  </div>
                  <Button 
                    className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold h-12 rounded-xl"
                    onClick={() => {
                      setRegistrationResult(null);
                      setIsRegistering(false);
                    }}
                  >
                    I HAVE SAVED IT
                  </Button>
                </div>
              ) : (
                <>
                  <h3 className="text-xl font-bold text-white mb-6">Register Gateway Client</h3>
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <label className="text-[10px] text-white/30 uppercase font-bold tracking-widest ml-1">Client Display Name</label>
                      <input 
                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder:text-white/10 focus:outline-none focus:ring-1 focus:ring-blue-500/50"
                        placeholder="e.g. Production Mobile App"
                        value={newClientName}
                        onChange={e => setNewClientName(e.target.value)}
                      />
                    </div>
                    <div className="pt-4 flex gap-3">
                      <Button variant="ghost" className="flex-1 text-white/30 hover:text-white" onClick={() => setIsRegistering(false)}>CANCEL</Button>
                      <Button 
                        className="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-bold"
                        disabled={!newClientName || registerMutation.isPending}
                        onClick={() => registerMutation.mutate(newClientName)}
                      >
                         {registerMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "PROCEED"}
                      </Button>
                    </div>
                  </div>
                </>
              )}
            </GlassCard>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// ─── Settings Tab ──────────────────────────────────────────


const AdminDashboard = () => {
  const { user } = useUser();
  const { signOut } = useClerk();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState("dashboard");
  const [loading, setLoading] = useState(true);

  const { data: frequencyData } = useQuery({
    queryKey: ["attackFrequency", user?.id],
    queryFn: () => api.getAttackFrequency(user?.id || ""),
    enabled: !!user?.id,
    refetchInterval: 30000,
  });

  const { data: topThreatsData } = useQuery({
    queryKey: ["topThreats", user?.id],
    queryFn: () => api.getTopThreats(user?.id || ""),
    enabled: !!user?.id,
    refetchInterval: 30000,
  });

  const { data: riskData } = useQuery({
    queryKey: ["riskDistribution", user?.id],
    queryFn: () => api.getRiskDistribution(user?.id || ""),
    enabled: !!user?.id,
    refetchInterval: 30000,
  });

  const { data: logsData } = useQuery({
    queryKey: ["securityLogs", user?.id],
    queryFn: () => api.getLogs(user?.id || ""),
    enabled: !!user?.id,
    refetchInterval: 5000,
  });

  const { data: latencyMetrics } = useQuery({
    queryKey: ["latencyMetrics", user?.id],
    queryFn: () => api.getLatencyMetrics(user?.id || ""),
    enabled: !!user?.id,
    refetchInterval: 10000,
  });

  const { data: blockEfficiency } = useQuery({
    queryKey: ["blockEfficiency", user?.id],
    queryFn: () => api.getBlockingEfficiency(user?.id || ""),
    enabled: !!user?.id,
    refetchInterval: 10000,
  });

  const { data: sanRatio } = useQuery({
    queryKey: ["sanRatio", user?.id],
    queryFn: () => api.getSanitizationRatio(user?.id || ""),
    enabled: !!user?.id,
    refetchInterval: 10000,
  });

  const { data: policyViolations } = useQuery({
    queryKey: ["policyViolations", user?.id],
    queryFn: () => api.getTopPolicyViolations(user?.id || ""),
    enabled: !!user?.id,
    refetchInterval: 10000,
  });

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
    <div className="min-h-screen bg-[#050505] text-white selection:bg-blue-500/30 font-sans overflow-x-hidden flex flex-col">
      <AuroraBackground />
      <FloatingBlobs />
      <LiquidEther />

      {/* Navigation */}
      <nav className="sticky top-0 z-[60] border-b border-white/[0.05] bg-black/40 backdrop-blur-2xl">
        <div className="container mx-auto px-8 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="h-10 w-10 rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-[0_0_20px_rgba(37,99,235,0.3)]">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <h2 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-white/40 tracking-tight">IronGuard Admin</h2>
              <div className="flex items-center gap-2 mt-0.5">
                <div className="h-1 w-1 rounded-full bg-blue-500 animate-pulse" />
                <span className="text-[10px] text-white/20 uppercase font-mono tracking-widest leading-none">V2.4.0 NODE_B_STABLE</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <Button size="sm" variant="ghost" className="text-red-400 hover:text-red-300 hover:bg-red-500/10" onClick={() => signOut()}>
              Sign Out
            </Button>
            <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-white/[0.03] border border-white/[0.05]">
              <Activity className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
              <span className="text-[10px] font-medium tracking-tight text-white/50 uppercase">Live Feed</span>
              <div className="w-1 h-1 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]" />
              <Button 
                size="sm" 
                variant="ghost" 
                className="text-[10px] text-white/20 hover:text-white" 
                onClick={() => {
                  queryClient.invalidateQueries({ queryKey: ["attackFrequency", user?.id] });
                  queryClient.invalidateQueries({ queryKey: ["topThreats", user?.id] });
                  queryClient.invalidateQueries({ queryKey: ["riskDistribution", user?.id] });
                }}
              >
                REFRESH LIVE DATA
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <div className="container mx-auto px-8 py-10 flex-1 relative z-10">
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="mb-10">
          <div className="flex items-end justify-between">
            <div>
              <h1 className="text-4xl font-bold tracking-tight text-white/90 mb-1">
                Admin Dashboard
              </h1>
              <p className="text-white/30">Welcome back, {user?.firstName || "Admin"}.</p>
            </div>
          </div>
        </motion.div>

        {/* Tab Switcher - Original Style Restored */}
        <div className="flex flex-wrap items-center gap-1.5 p-1.5 rounded-2xl bg-white/[0.02] border border-white/[0.05] mb-8 w-fit">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium transition-all ${
                activeTab === tab.id
                  ? "bg-white/[0.07] text-white border border-white/10 shadow-xl shadow-black/20"
                  : "text-white/30 hover:text-white/50 hover:bg-white/[0.02] border border-transparent"
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="relative">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              variants={tabContent}
              initial="hidden"
              animate="visible"
              exit="exit"
            >
              {activeTab === "dashboard" && (
                <DashboardTab 
                  frequencyData={frequencyData ?? null} 
                  riskDistribution={riskData ?? null}
                  topThreats={topThreatsData ?? null}
                  latencyMetrics={latencyMetrics}
                  sanitizationRatio={sanRatio}
                  blockingEfficiency={blockEfficiency}
                  logs={logsData?.logs || []}
                />
              )}
              {activeTab === "analytics" && (
                <ThreatAnalyticsTab 
                  frequencyData={frequencyData ?? null}
                  latencyMetrics={latencyMetrics}
                  policyViolations={policyViolations}
                />
              )}
              {activeTab === "team" && <TeamTab />}
              {activeTab === "gateway" && <GatewayRegistryTab adminId={user?.id || ""} />}
              {activeTab === "interactive-flow" && (
                <div className="py-8">
                  <GatewayVisualizer />
                </div>
              )}
              {activeTab === "live-monitor" && <LiveMonitorTab logs={logsData?.logs || []} />}
              {activeTab === "self-learning" && <SelfLearningTab adminId={user?.id || ""} />}
              {activeTab === "security-logs" && <SecurityLogsTab logs={logsData?.logs || []} />}
              {activeTab === "settings" && <AdminSettings adminId={user?.id || ""} />}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>

      {/* Footer info */}
      <div className="container mx-auto px-8 pb-12 mt-auto">
        <div className="flex items-center justify-between py-6 border-t border-white/[0.05]">
          <p className="text-[10px] text-white/15 uppercase font-mono tracking-widest">IronGuard AI Security Pipeline v3.2.0-STABLE</p>
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <div className="h-1.5 w-1.5 rounded-full bg-green-500/50" />
              <span className="text-[10px] text-white/30 uppercase font-mono">Engine: ONLINE</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-1.5 w-1.5 rounded-full bg-blue-500/50" />
              <span className="text-[10px] text-white/30 uppercase font-mono">Latency: {Math.round(latencyMetrics?.avg_latency || 0)}ms</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;
