import { Shield } from "lucide-react";
import { motion } from "framer-motion";
import { SignIn, SignUp } from "@clerk/clerk-react";
import AuroraBackground from "@/components/ui/AuroraBackground";
import ParticleField from "@/components/ui/ParticleField";
import FloatingBlobs from "@/components/ui/FloatingBlobs";
import LiquidEther from "@/components/ui/LiquidEther";
import ElectricBorder from "@/components/ui/ElectricBorder";
import { useState } from "react";

const Login = () => {
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
                afterSignInUrl="/dashboard"
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
                afterSignUpUrl="/dashboard"
                signInUrl="#login"
              />
            )}
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
