import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Shield, Key, Plus, Trash2, CheckCircle2, AlertTriangle, Loader2, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "@/hooks/use-toast";

const GlassCard = ({ children, className = "" }: { children: React.ReactNode; className?: string }) => (
  <div className={`rounded-2xl border border-white/[0.06] bg-black/40 backdrop-blur-xl ${className}`}>
    {children}
  </div>
);

const AdminSettings = ({ adminId }: { adminId: string }) => {
  const queryClient = useQueryClient();
  const [newProvider, setNewProvider] = useState("gemini");
  const [newKey, setNewKey] = useState("");

  const { data: keys, isLoading } = useQuery({
    queryKey: ["providerKeys", adminId],
    queryFn: () => api.listProviderKeys(adminId),
  });

  const storeMutation = useMutation({
    mutationFn: (data: { provider: string; key: string }) => 
      api.storeProviderKey(adminId, data.provider, data.key),
    onSuccess: (data) => {
      toast({ title: "Success", description: data.message });
      setNewKey("");
      queryClient.invalidateQueries({ queryKey: ["providerKeys"] });
    },
    onError: (err: any) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    }
  });

  const deleteMutation = useMutation({
    mutationFn: (provider: string) => api.deleteProviderKey(adminId, provider),
    onSuccess: (data: any) => {
      toast({ title: "Revoked", description: data.message });
      queryClient.invalidateQueries({ queryKey: ["providerKeys"] });
    }
  });

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      <header className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold bg-gradient-to-r from-white to-white/40 bg-clip-text text-transparent">
          Secure Key Vault
        </h1>
        <p className="text-white/40 text-sm max-w-xl">
          Manage AI provider credentials securely. Keys are encrypted using AES-256 (Fernet) and never exposed to employees.
        </p>
      </header>

      <div className="grid lg:grid-cols-3 gap-8">
        {/* Registration Form */}
        <GlassCard className="p-6 h-fit lg:col-span-1">
          <div className="flex items-center gap-2 mb-6 text-amber-500/80">
            <Plus className="h-4 w-4" />
            <h2 className="text-xs font-bold uppercase tracking-widest">Register Provider</h2>
          </div>
          
          <div className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-[10px] text-white/30 uppercase font-bold ml-1">AI Provider</label>
              <select 
                value={newProvider}
                onChange={(e) => setNewProvider(e.target.value)}
                className="w-full bg-white/[0.03] border border-white/[0.08] rounded-xl px-4 py-3 text-sm text-white/80 focus:outline-none focus:ring-1 focus:ring-amber-500/50 appearance-none"
              >
                <option value="gemini" className="bg-[#111]">Google Gemini</option>
                <option value="mistral" className="bg-[#111]">Mistral AI</option>
                <option value="openai" className="bg-[#111]">OpenAI</option>
                <option value="anthropic" className="bg-[#111]">Anthropic</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] text-white/30 uppercase font-bold ml-1">API Key</label>
              <div className="relative">
                <input
                  type="password"
                  placeholder="sk-..."
                  value={newKey}
                  onChange={(e) => setNewKey(e.target.value)}
                  className="w-full bg-white/[0.03] border border-white/[0.08] rounded-xl pl-10 pr-4 py-3 text-sm text-white/80 placeholder:text-white/10 focus:outline-none focus:ring-1 focus:ring-amber-500/50"
                />
                <Key className="absolute left-3.5 top-3.5 h-4 w-4 text-white/20" />
              </div>
            </div>

            <Button 
              className="w-full bg-amber-500 hover:bg-amber-600 text-black font-bold h-12 rounded-xl mt-4"
              disabled={!newKey || storeMutation.isPending}
              onClick={() => storeMutation.mutate({ provider: newProvider, key: newKey })}
            >
              {storeMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Store Securely"}
            </Button>
            
            <p className="text-[10px] text-white/20 leading-relaxed text-center mt-4 italic">
              Once stored, the raw key is never returned by the API. It is only used by the Proxy at runtime.
            </p>
          </div>
        </GlassCard>

        {/* Active Keys List */}
        <div className="lg:col-span-2 space-y-4">
           <div className="flex items-center gap-2 mb-2 text-blue-400/80">
            <Server className="h-4 w-4" />
            <h2 className="text-xs font-bold uppercase tracking-widest">Active Credentials</h2>
          </div>

          {isLoading ? (
            <div className="h-40 flex items-center justify-center">
              <Loader2 className="h-6 w-6 text-white/20 animate-spin" />
            </div>
          ) : keys?.length === 0 ? (
            <div className="h-64 rounded-2xl border border-dashed border-white/5 flex flex-col items-center justify-center text-white/10 gap-2">
              <Key className="h-8 w-8 opacity-20" />
              <p className="text-sm italic">No providers configured in vault</p>
            </div>
          ) : (
            <div className="grid gap-3">
              {keys?.map((key: any) => (
                <GlassCard key={key.provider} className="p-4 flex items-center justify-between group overflow-hidden relative">
                   <div className="absolute inset-0 bg-gradient-to-r from-blue-500/[0.02] to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                  
                   <div className="flex items-center gap-4 relative z-10">
                    <div className="h-10 w-10 rounded-xl bg-white/[0.03] border border-white/[0.05] flex items-center justify-center">
                      <Shield className="h-5 w-5 text-white/30" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white/80 uppercase tracking-tight">{key.provider}</h3>
                      <div className="flex items-center gap-2 mt-0.5">
                        <CheckCircle2 className="h-3 w-3 text-green-500/50" />
                        <span className="text-[10px] text-white/30 uppercase font-mono">
                          Secured via Fernet-AES256 • Updated {new Date(key.updated_at).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 relative z-10">
                    <div className="px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-[9px] text-blue-400 font-bold uppercase tracking-widest">
                      In Use
                    </div>
                    <Button 
                      variant="ghost" 
                      size="icon" 
                      className="h-9 w-9 text-red-500/40 hover:text-red-500 hover:bg-red-500/10 rounded-xl transition-colors"
                      onClick={() => {
                        if (confirm(`Revoke key for ${key.provider}? All associated LLM calls will fail.`)) {
                          deleteMutation.mutate(key.provider);
                        }
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </GlassCard>
              ))}
            </div>
          )}

          <div className="p-4 rounded-xl bg-amber-500/5 border border-amber-500/10 flex items-start gap-4 mt-8">
            <AlertTriangle className="h-5 w-5 text-amber-500/40 mt-0.5" />
            <div className="space-y-1">
              <p className="text-xs font-bold text-amber-500/60 uppercase tracking-widest">Security Warning</p>
              <p className="text-[11px] text-white/40 leading-relaxed">
                Revoking a key immediately breaks all proxy requests for that provider. Ensure you have a fallback configured in <code className="text-amber-500/40">llm_proxy.py</code> or another provider registered in this vault.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminSettings;
