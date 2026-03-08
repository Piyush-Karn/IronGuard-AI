import { useState } from "react";
import { Shield, ShieldCheck, User } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { SignIn, SignUp } from "@clerk/clerk-react";
import ElectricBorder from "@/components/ui/ElectricBorder";
import AuroraBackground from "@/components/ui/AuroraBackground";
import ParticleField from "@/components/ui/ParticleField";
import FloatingBlobs from "@/components/ui/FloatingBlobs";
import LiquidEther from "@/components/ui/LiquidEther";

type Step = "role" | "auth";
type Role = "admin" | "user";

const Login = () => {
  const [step, setStep] = useState<Step>("role");
  const [role, setRole] = useState<Role>("user");
  const [mode, setMode] = useState<"login" | "signup">("login");

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center px-4 relative bg-black"
      style={{ fontFamily: "'Space Grotesk','Inter',system-ui,sans-serif" }}
    >
      <div className="absolute inset-0 overflow-hidden">
        <AuroraBackground />
        <LiquidEther />
        <ParticleField />
        <FloatingBlobs />
      </div>

      {/* Top branding */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
        className="relative z-10 text-center mb-10"
      >
        <div className="flex items-center justify-center gap-3 mb-3">
          <div className="h-11 w-11 rounded-2xl bg-white/[0.08] border border-white/[0.08] flex items-center justify-center backdrop-blur-xl">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-b from-white to-white/50 bg-clip-text text-transparent">
            IronGuard AI
          </h1>
        </div>
        <p className="text-white/30 text-sm tracking-wide">
          AI-Powered Prompt Security Platform
        </p>
      </motion.div>

      {/* Login container */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
        className="w-full max-w-md relative z-10"
      >
        <ElectricBorder color="#7df9ff" speed={1} chaos={0.15} borderRadius={24}>
        <div className="rounded-3xl p-8 bg-[rgba(8,8,16,0.92)] backdrop-blur-2xl shadow-[0_0_80px_rgba(0,0,0,0.4)]">
          <AnimatePresence mode="wait">
            {step === "role" && (
              <motion.div
                key="role"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
              >
                <h2 className="text-white/80 text-center font-semibold text-lg mb-2">
                  Select Your Role
                </h2>
                <p className="text-white/30 text-center text-xs mb-8">
                  Choose how you want to access the platform
                </p>
                <div className="grid grid-cols-2 gap-4">
                  <button
                    onClick={() => { setRole("admin"); setStep("auth"); }}
                    className="rounded-2xl p-6 bg-white/[0.03] border border-white/[0.06] hover:bg-white/[0.07] hover:border-white/[0.14] transition-all duration-500 group relative overflow-hidden"
                  >
                    <div className="absolute inset-0 bg-gradient-to-b from-indigo-500/[0.04] to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                    <div className="relative">
                      <div className="h-12 w-12 rounded-xl bg-white/[0.06] border border-white/[0.08] flex items-center justify-center mx-auto mb-4 group-hover:bg-white/[0.1] transition-colors duration-500">
                        <ShieldCheck className="h-5 w-5 text-white/60 group-hover:text-white transition-colors duration-300" />
                      </div>
                      <p className="text-white font-semibold text-sm mb-1">Admin</p>
                      <p className="text-[11px] text-white/30">System Owner</p>
                    </div>
                  </button>
                  <button
                    onClick={() => { setRole("user"); setStep("auth"); }}
                    className="rounded-2xl p-6 bg-white/[0.03] border border-white/[0.06] hover:bg-white/[0.07] hover:border-white/[0.14] transition-all duration-500 group relative overflow-hidden"
                  >
                    <div className="absolute inset-0 bg-gradient-to-b from-cyan-500/[0.04] to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                    <div className="relative">
                      <div className="h-12 w-12 rounded-xl bg-white/[0.06] border border-white/[0.08] flex items-center justify-center mx-auto mb-4 group-hover:bg-white/[0.1] transition-colors duration-500">
                        <User className="h-5 w-5 text-white/60 group-hover:text-white transition-colors duration-300" />
                      </div>
                      <p className="text-white font-semibold text-sm mb-1">Employee</p>
                      <p className="text-[11px] text-white/30">User Access</p>
                    </div>
                  </button>
                </div>
              </motion.div>
            )}

            {step === "auth" && (
              <motion.div
                key="auth"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
              >
                <button
                  onClick={() => setStep("role")}
                  className="text-white/30 hover:text-white/60 text-xs mb-5 flex items-center gap-1 transition-colors duration-300"
                >
                  ← Back to roles
                </button>

                <div className="flex bg-white/[0.04] rounded-xl p-1 mb-7 border border-white/[0.08]">
                  <button
                    onClick={() => setMode("login")}
                    className={`flex-1 py-2.5 rounded-lg text-sm font-medium transition-all duration-300 ${
                      mode === "login" ? "bg-white text-black shadow-sm" : "text-white/50 hover:text-white/70"
                    }`}
                  >
                    Login
                  </button>
                  <button
                    onClick={() => setMode("signup")}
                    className={`flex-1 py-2.5 rounded-lg text-sm font-medium transition-all duration-300 ${
                      mode === "signup" ? "bg-white text-black shadow-sm" : "text-white/50 hover:text-white/70"
                    }`}
                  >
                    Sign Up
                  </button>
                </div>

                {mode === "login" ? (
                  <SignIn
                    routing="hash"
                    appearance={{
                      elements: {
                        rootBox: "w-full",
                        card: "bg-transparent shadow-none border-0 p-0",
                        headerTitle: "hidden",
                        headerSubtitle: "hidden",
                        socialButtonsBlockButton:
                          "bg-white/[0.05] border border-white/[0.08] text-white hover:bg-white/[0.1] transition-all duration-300 rounded-xl h-11",
                        socialButtonsBlockButtonText: "text-white text-sm",
                        formFieldInput:
                          "bg-white/[0.05] border border-white/[0.08] text-white placeholder:text-white/40 rounded-xl h-11",
                        formButtonPrimary:
                          "bg-white text-black hover:bg-white/90 transition-all duration-300 rounded-xl h-11 font-medium",
                        footerActionLink: "text-white/60 hover:text-white transition-colors duration-300",
                        dividerLine: "bg-white/[0.08]",
                        dividerText: "text-white/30 text-xs",
                      },
                    }}
                    afterSignInUrl={role === "admin" ? "/admin" : "/user/analyser"}
                    signUpUrl="#signup"
                  />
                ) : (
                  <SignUp
                    routing="hash"
                    appearance={{
                      elements: {
                        rootBox: "w-full",
                        card: "bg-transparent shadow-none border-0 p-0",
                        headerTitle: "hidden",
                        headerSubtitle: "hidden",
                        socialButtonsBlockButton:
                          "bg-white/[0.05] border border-white/[0.08] text-white hover:bg-white/[0.1] transition-all duration-300 rounded-xl h-11",
                        socialButtonsBlockButtonText: "text-white text-sm",
                        formFieldInput:
                          "bg-white/[0.05] border border-white/[0.08] text-white placeholder:text-white/40 rounded-xl h-11",
                        formButtonPrimary:
                          "bg-white text-black hover:bg-white/90 transition-all duration-300 rounded-xl h-11 font-medium",
                        footerActionLink: "text-white/60 hover:text-white transition-colors duration-300",
                        dividerLine: "bg-white/[0.08]",
                        dividerText: "text-white/30 text-xs",
                      },
                    }}
                    afterSignUpUrl={role === "admin" ? "/admin" : "/user/analyser"}
                    signInUrl="#login"
                  />
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
        </ElectricBorder>

        <p className="text-center text-[11px] text-white/20 mt-8 tracking-wide">
          Protected by IronGuard AI Security
        </p>
      </motion.div>
    </div>
  );
};

export default Login;
