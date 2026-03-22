import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, GatewayClient } from "@/lib/api";
import { useUser, useClerk } from "@clerk/clerk-react";
import { 
  Shield, 
  Plus, 
  RefreshCw, 
  Trash2, 
  Key, 
  Copy, 
  Check, 
  Search,
  LayoutDashboard,
  Users,
  Activity,
  AlertTriangle,
  Clock,
  ExternalLink,
  Zap,
  Lock
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "@/hooks/use-toast";
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogDescription,
  DialogFooter
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import LiquidEther from "@/components/ui/LiquidEther";
import AuroraBackground from "@/components/ui/AuroraBackground";
import FloatingBlobs from "@/components/ui/FloatingBlobs";

const GlassCard = ({ children, className = "" }: { children: React.ReactNode; className?: string }) => (
  <div className={`rounded-2xl border border-white/[0.06] bg-black/40 backdrop-blur-xl ${className}`}>
    {children}
  </div>
);

const AdminGateway = () => {
  const { user } = useUser();
  const { signOut } = useClerk();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [isRegisterOpen, setIsRegisterOpen] = useState(false);
  const [newClientName, setNewClientName] = useState("");
  const [newClientRPM, setNewClientRPM] = useState("60");
  const [registrationResult, setRegistrationResult] = useState<any>(null);
  const [copied, setCopied] = useState(false);

  const { data: clientsData, isLoading } = useQuery({
    queryKey: ["gatewayClients", user?.id],
    queryFn: () => api.getGatewayClients(user?.id || ""),
    enabled: !!user?.id,
    refetchInterval: 10000,
  });

  const registerMutation = useMutation({
    mutationFn: (data: { client_name: string, allowed_rpm: number }) => 
      api.registerGatewayClient(user?.id || "", data),
    onSuccess: (data) => {
      setRegistrationResult(data);
      queryClient.invalidateQueries({ queryKey: ["gatewayClients"] });
      toast({ title: "Client Registered", description: "Backend client created successfully." });
    },
    onError: (err: any) => {
      toast({ title: "Registration Failed", description: err.message, variant: "destructive" });
    }
  });

  const rotateMutation = useMutation({
    mutationFn: (clientId: string) => api.rotateGatewaySecret(user?.id || "", clientId),
    onSuccess: (data) => {
      setRegistrationResult(data);
      queryClient.invalidateQueries({ queryKey: ["gatewayClients"] });
      toast({ title: "Secret Rotated", description: "New signing secret generated." });
    }
  });

  const revokeMutation = useMutation({
    mutationFn: ({ clientId, reason }: { clientId: string, reason: string }) => 
      api.revokeGatewayClient(user?.id || "", clientId, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["gatewayClients"] });
      toast({ title: "Client Revoked", description: "Access has been disabled." });
    }
  });

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const clients = (clientsData?.clients || []).filter(c => 
    c.client_name.toLowerCase().includes(search.toLowerCase()) || 
    c.client_id.includes(search)
  );

  return (
    <div className="min-h-screen bg-[#050508] text-white relative overflow-x-hidden" style={{ fontFamily: "'Space Grotesk','Inter',system-ui,sans-serif" }}>
      <LiquidEther />
      <div className="fixed inset-0 pointer-events-none">
        <AuroraBackground />
        <FloatingBlobs />
      </div>

      <nav className="sticky top-0 z-50 border-b border-white/[0.04] bg-black/50 backdrop-blur-2xl">
        <div className="container mx-auto flex items-center justify-between h-16 px-4 md:px-8">
          <div className="flex items-center gap-2.5">
            <div className="h-8 w-8 rounded-lg bg-white/[0.06] border border-white/[0.06] flex items-center justify-center">
              <Shield className="h-4 w-4 text-white/70" />
            </div>
            <span className="text-base font-semibold tracking-tight text-white/90">IronGuard AI — Gateway</span>
          </div>
          <div className="flex items-center gap-4">
            <Button 
                size="sm" 
                variant="ghost" 
                className="text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 text-xs h-8" 
                onClick={() => window.location.href = "/admin"}
            >
              <LayoutDashboard className="h-3 w-3 mr-1.5" /> Dashboard
            </Button>
            <span className="text-sm text-white/35 hidden md:inline">{user?.primaryEmailAddress?.emailAddress}</span>
            <Button size="sm" variant="ghost" className="text-red-400 hover:text-red-300 hover:bg-red-500/10" onClick={() => signOut()}>
              Sign Out
            </Button>
          </div>
        </div>
      </nav>

      <div className="container mx-auto px-4 md:px-8 py-10 relative z-10">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-12">
          <div>
            <h1 className="text-4xl font-bold mb-2 bg-gradient-to-b from-white to-white/50 bg-clip-text text-transparent">
              Client Registry
            </h1>
            <p className="text-white/30">Provision and manage HMAC-signed credentials for backend integrations.</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="relative group">
               <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-white/20 group-focus-within:text-white/40 transition-colors" />
               <Input 
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search clients..." 
                className="pl-9 h-10 w-full md:w-64 bg-white/5 border-white/[0.08] text-sm rounded-xl focus:ring-0 focus:border-white/20"
               />
            </div>
            <Button 
              onClick={() => setIsRegisterOpen(true)}
              className="bg-white text-black hover:bg-white/90 h-10 px-5 rounded-xl font-medium gap-2 shadow-[0_0_20px_rgba(255,255,255,0.08)]"
            >
              <Plus className="h-4 w-4" /> REGISTER CLIENT
            </Button>
          </div>
        </motion.div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            {[
              { label: "Total Clients", value: clients.length, icon: Users, color: "text-blue-400" },
              { label: "Active Nodes", value: clients.filter(c => c.is_active).length, icon: Activity, color: "text-green-400" },
              { label: "Gateway Requests", value: clients.reduce((acc, c) => acc + c.request_count, 0).toLocaleString(), icon: Zap, color: "text-amber-400" },
              { label: "Security Status", value: "Verified", icon: Shield, color: "text-cyan-400" },
            ].map((s, i) => (
              <motion.div key={i} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}>
                <GlassCard className="p-5 border-white/[0.04]">
                  <div className="flex items-center gap-2 mb-3">
                    <s.icon className={`h-3.5 w-3.5 ${s.color} opacity-60`} />
                    <span className="text-[10px] uppercase tracking-widest text-white/20 font-bold">{s.label}</span>
                  </div>
                  <p className="text-3xl font-bold text-white/90 tracking-tight">{s.value}</p>
                </GlassCard>
              </motion.div>
            ))}
        </div>

        {/* Clients List */}
        <div className="space-y-4">
          {isLoading ? (
            <div className="h-64 flex flex-col items-center justify-center gap-4 text-white/20">
              <RefreshCw className="h-8 w-8 animate-spin" />
              <p className="text-xs uppercase tracking-widest">Hydrating Registry...</p>
            </div>
          ) : clients.length === 0 ? (
            <div className="h-64 flex flex-col items-center justify-center gap-4 border border-dashed border-white/10 rounded-3xl text-white/10 uppercase tracking-widest text-xs">
              No clients found matching "{search}"
            </div>
          ) : (
            clients.map((client, i) => (
              <motion.div 
                key={client.client_id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <GlassCard className={`p-6 transition-all duration-300 hover:border-white/10 group ${!client.is_active ? 'opacity-50' : ''}`}>
                  <div className="flex flex-col lg:flex-row lg:items-center gap-6">
                    <div className="flex items-start gap-4 flex-1">
                      <div className={`h-12 w-12 rounded-2xl flex items-center justify-center border transition-colors ${client.is_active ? 'bg-indigo-500/10 border-indigo-500/20 text-indigo-400' : 'bg-white/5 border-white/10 text-white/20'}`}>
                        <Key className="h-6 w-6" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-1">
                          <h3 className="text-lg font-bold text-white/80">{client.client_name}</h3>
                          {!client.is_active && (
                            <span className="px-2 py-0.5 rounded text-[8px] font-bold bg-red-500/10 text-red-400 uppercase">Revoked</span>
                          )}
                        </div>
                        <div className="flex items-center gap-4">
                          <code className="text-xs text-white/20 font-mono flex items-center gap-2">
                             ID: {client.client_id}
                             <button onClick={() => handleCopy(client.client_id)} className="hover:text-white/40 transition-colors">
                               <Copy className="h-3 w-3" />
                             </button>
                          </code>
                          <span className="h-1 w-1 rounded-full bg-white/10" />
                          <span className="text-[10px] text-white/20 uppercase font-bold tracking-tighter">
                            RPM LIMIT: {client.allowed_rpm}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-3 gap-8 lg:gap-12 px-2">
                        <div>
                          <p className="text-[9px] uppercase font-bold text-white/15 tracking-widest mb-1.5 flex items-center gap-1.5">
                            <Clock className="h-2.5 w-2.5 text-white/30" /> LAST ACTIVITY
                          </p>
                          <p className="text-xs text-white/40 font-mono">
                            {client.last_used ? new Date(client.last_used).toLocaleTimeString() : 'NEVER'}
                          </p>
                        </div>
                        <div>
                          <p className="text-[9px] uppercase font-bold text-white/15 tracking-widest mb-1.5 flex items-center gap-1.5">
                            <Activity className="h-2.5 w-2.5 text-white/30" /> REQUESTS
                          </p>
                          <p className="text-xs text-white/40 font-mono">
                            {(client.request_count || 0).toLocaleString()}
                          </p>
                        </div>
                        <div className="hidden md:block">
                          <p className="text-[9px] uppercase font-bold text-white/15 tracking-widest mb-1.5 flex items-center gap-1.5">
                            <Users className="h-2.5 w-2.5 text-white/30" /> CREATED BY
                          </p>
                          <p className="text-xs text-white/40 font-mono truncate max-w-[100px]">
                            {client.created_by}
                          </p>
                        </div>
                    </div>

                    <div className="flex items-center gap-2 lg:ml-4">
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        title="Rotate Secret"
                        onClick={() => rotateMutation.mutate(client.client_id)}
                        disabled={!client.is_active || rotateMutation.isPending}
                        className="h-9 w-9 p-0 text-amber-400/40 hover:text-amber-400 hover:bg-amber-400/10 rounded-xl"
                      >
                        <RefreshCw className={`h-4 w-4 ${rotateMutation.isPending ? 'animate-spin' : ''}`} />
                      </Button>
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        title="Revoke Access"
                        onClick={() => {
                          const reason = window.prompt("Reason for revocation?");
                          if (reason) revokeMutation.mutate({ clientId: client.client_id, reason });
                        }}
                        disabled={!client.is_active || revokeMutation.isPending}
                        className="h-9 w-9 p-0 text-red-500/40 hover:text-red-500 hover:bg-red-500/10 rounded-xl"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </GlassCard>
              </motion.div>
            ))
          )}
        </div>
      </div>

      {/* Register Modal */}
      <Dialog open={isRegisterOpen} onOpenChange={setIsRegisterOpen}>
         <DialogContent className="bg-[#0a0a0c] border-white/10 text-white rounded-3xl max-w-md">
            <DialogHeader>
               <DialogTitle className="text-xl font-bold">Register Gateway Client</DialogTitle>
               <DialogDescription className="text-white/40">
                  Provision new HMAC credentials for your external backend service.
               </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
               <div className="space-y-2">
                  <Label className="text-xs text-white/40 uppercase font-bold tracking-widest">Client Name</Label>
                  <Input 
                    value={newClientName}
                    onChange={e => setNewClientName(e.target.value)}
                    placeholder="e.g. Production HR Chatbot" 
                    className="bg-white/5 border-white/10 rounded-xl"
                  />
               </div>
               <div className="space-y-2">
                  <Label className="text-xs text-white/40 uppercase font-bold tracking-widest">Rate Limit (RPM)</Label>
                  <Input 
                    type="number"
                    value={newClientRPM}
                    onChange={e => setNewClientRPM(e.target.value)}
                    className="bg-white/5 border-white/10 rounded-xl"
                  />
               </div>
            </div>
            <DialogFooter>
               <Button 
                variant="ghost" 
                onClick={() => setIsRegisterOpen(false)}
                className="text-white/30 hover:text-white"
               >
                 CANCEL
               </Button>
               <Button 
                 onClick={() => {
                    registerMutation.mutate({ client_name: newClientName, allowed_rpm: parseInt(newClientRPM) });
                    setIsRegisterOpen(false);
                 }}
                 disabled={!newClientName || registerMutation.isPending}
                 className="bg-white text-black hover:bg-white/90 rounded-xl"
               >
                 {registerMutation.isPending ? 'CREATING...' : 'GENERATE CREDENTIALS'}
               </Button>
            </DialogFooter>
         </DialogContent>
      </Dialog>

      {/* Secret Result Modal */}
      <Dialog open={!!registrationResult} onOpenChange={() => setRegistrationResult(null)}>
         <DialogContent className="bg-[#0a0a0c] border-white/10 text-white rounded-3xl max-w-md">
            <DialogHeader>
               <div className="h-12 w-12 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center mb-4">
                  <AlertTriangle className="h-6 w-6 text-amber-500" />
               </div>
               <DialogTitle className="text-xl font-bold">Secure Credentials Generated</DialogTitle>
               <DialogDescription className="text-white/40">
                  Store the secret key securely. For security reasons, it will **never** be shown again.
               </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
               <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/[0.05] space-y-4">
                  <div className="space-y-1">
                     <p className="text-[10px] text-white/20 uppercase font-bold">Client ID</p>
                     <p className="text-sm font-mono text-white/80">{registrationResult?.client_id}</p>
                  </div>
                  <div className="space-y-1">
                     <p className="text-[10px] text-white/20 uppercase font-bold">Signing Secret (HMAC Key)</p>
                     <div className="flex items-center gap-3">
                        <code className="text-sm font-mono text-amber-400 bg-amber-400/5 px-2 py-1 rounded flex-1 truncate">
                          {registrationResult?.secret || registrationResult?.new_secret}
                        </code>
                        <Button 
                          size="sm" 
                          variant="ghost" 
                          onClick={() => handleCopy(registrationResult?.secret || registrationResult?.new_secret)}
                          className="h-8 w-8 p-0 text-white/40 hover:text-white"
                        >
                          {copied ? <Check className="h-4 w-4 text-green-400" /> : <Copy className="h-4 w-4" />}
                        </Button>
                     </div>
                  </div>
               </div>
               <p className="text-[10px] text-red-400/60 font-medium italic flex items-center gap-2 px-2">
                 <Lock className="h-3 w-3" /> If lost, you must rotate the secret to regain access.
               </p>
            </div>
            <DialogFooter>
               <Button 
                 onClick={() => setRegistrationResult(null)}
                 className="w-full bg-white text-black hover:bg-white/90 rounded-xl"
               >
                 I HAVE STORED THE KEY SECURELY
               </Button>
            </DialogFooter>
         </DialogContent>
      </Dialog>
    </div>
  );
};

export default AdminGateway;
