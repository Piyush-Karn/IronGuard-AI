import React, { useState } from "react";
import { useUser } from "@clerk/clerk-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { ShieldAlert, ShieldCheck, Lock, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { motion, AnimatePresence } from "framer-motion";

interface VerificationWallProps {
  children: React.ReactNode;
}

const VerificationWall: React.FC<VerificationWallProps> = ({ children }) => {
  const { user } = useUser();
  const queryClient = useQueryClient();
  const [secret, setSecret] = useState("");
  const [isVerifying, setIsVerifying] = useState(false);

  const { data: roleData, isLoading, isError } = useQuery({
    queryKey: ["userRole", user?.id],
    queryFn: () => api.getUserRole(user?.id || ""),
    enabled: !!user?.id,
  });

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!secret.trim() || !user?.id) return;

    setIsVerifying(true);
    try {
      await api.verifySecret(secret, user.id);
      toast.success("Account verified successfully!");
      // Invalidate query to trigger re-render with children
      queryClient.invalidateQueries({ queryKey: ["userRole", user.id] });
    } catch (error: any) {
      toast.error(error.message || "Invalid or expired secret");
    } finally {
      setIsVerifying(false);
    }
  };

  if (isError) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#050505] p-6">
        <Card className="bg-[#0A0A0A] border-red-500/20 shadow-2xl glassmorphism max-w-md w-full">
          <CardHeader className="text-center">
            <div className="mx-auto w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mb-4 border border-red-500/20">
              <ShieldAlert className="w-8 h-8 text-red-500" />
            </div>
            <CardTitle className="text-xl font-bold text-white">Security Sync Failed</CardTitle>
            <CardDescription className="text-gray-400 mt-2">
              We couldn't verify your security role. This might be a temporary connection issue.
            </CardDescription>
          </CardHeader>
          <CardFooter>
            <Button 
              onClick={() => queryClient.invalidateQueries({ queryKey: ["userRole", user?.id] })}
              className="w-full bg-white/5 hover:bg-white/10 text-white border border-white/10"
            >
              Retry Connection
            </Button>
          </CardFooter>
        </Card>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#050505]">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
      </div>
    );
  }

  // Admin and already verified employees pass through
  const role = roleData?.role?.toLowerCase();
  const isVerified = roleData?.is_verified;

  if (role === "admin" || isVerified) {
    return <>{children}</>;
  }

  console.log("[VerificationWall] Access Blocked:", { 
    userId: user?.id, 
    role, 
    isVerified,
    roleData 
  });

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#050505] p-6">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(59,130,246,0.05),transparent_70%)]" />
      
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md relative z-10"
      >
        <Card className="bg-[#0A0A0A] border-white/5 shadow-2xl overflow-hidden glassmorphism">
          <div className="h-1.5 w-full bg-gradient-to-r from-blue-600 to-indigo-600" />
          
          <CardHeader className="text-center pt-8">
            <div className="mx-auto w-16 h-16 bg-blue-500/10 rounded-full flex items-center justify-center mb-4 border border-blue-500/20">
              <Lock className="w-8 h-8 text-blue-500" />
            </div>
            <CardTitle className="text-2xl font-bold text-white tracking-tight">
              Authorization Required
            </CardTitle>
            <CardDescription className="text-gray-400 mt-2">
              To ensure system integrity, IronGuard requires a one-time authorization secret for your employee account.
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            <form id="verify-form" onSubmit={handleVerify} className="space-y-4">
              <div className="space-y-2">
                <Input
                  type="text"
                  placeholder="Enter authorization secret"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  maxLength={16}
                  className="bg-white/5 border-white/10 text-white h-12 focus:ring-blue-500"
                  disabled={isVerifying}
                />
                <p className="text-[11px] text-gray-500 text-center uppercase tracking-widest font-medium">
                  Secret provided by your Administrator
                </p>
              </div>
            </form>
          </CardContent>

          <CardFooter className="pb-8 pt-2">
            <Button
              form="verify-form"
              type="submit"
              disabled={isVerifying || !secret.trim()}
              className="w-full h-12 bg-blue-600 hover:bg-blue-700 text-white font-semibold transition-all duration-300 shadow-lg shadow-blue-500/20"
            >
              {isVerifying ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Verifying...
                </>
              ) : (
                "Verify Unlock Access"
              )}
            </Button>
          </CardFooter>
        </Card>

        <div className="mt-8 flex items-center justify-center gap-6 opacity-40 grayscale pointer-events-none">
          <div className="flex items-center gap-2 text-xs text-white uppercase tracking-tighter">
            <ShieldCheck className="w-4 h-4" />
            AES-256 Encrypted
          </div>
          <div className="flex items-center gap-2 text-xs text-white uppercase tracking-tighter">
            <ShieldAlert className="w-4 h-4" />
            Atomic Verification
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default VerificationWall;
