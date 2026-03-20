import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { SignedIn, SignedOut, useUser } from "@clerk/clerk-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./lib/api";
import Index from "./pages/Index";
import Login from "./pages/Login";
import AdminDashboard from "./pages/AdminDashboard";
import AdminGateway from "./pages/AdminGateway";
import UserAnalyser from "./pages/UserAnalyser";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => (
  <>
    <SignedIn>{children}</SignedIn>
    <SignedOut><Navigate to="/login" replace /></SignedOut>
  </>
);

const AdminRoute = ({ children }: { children: React.ReactNode }) => {
  const { user, isLoaded: isClerkLoaded } = useUser();
  
  const { data: roleData, isLoading: isRoleLoading } = useQuery({
    queryKey: ["userRole", user?.id],
    queryFn: () => api.getUserRole(
      user?.id || "",
      user?.primaryEmailAddress?.emailAddress,
      user?.fullName || user?.username || undefined
    ),
    enabled: isClerkLoaded && !!user,
    retry: false,
  });

  if (!isClerkLoaded || isRoleLoading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-[#050505] text-white">
        <div className="w-12 h-12 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin mb-4"></div>
        <p className="text-gray-400 animate-pulse">Verifying Credentials...</p>
      </div>
    );
  }

  if (roleData?.role !== "admin") {
    return <Navigate to="/user/analyser" replace />;
  }

  return <>{children}</>;
};

const DashboardRedirect = () => {
  const { user, isLoaded: isClerkLoaded } = useUser();
  
  const { data: roleData, isLoading: isRoleLoading } = useQuery({
    queryKey: ["userRole", user?.id],
    queryFn: () => api.getUserRole(
      user?.id || "",
      user?.primaryEmailAddress?.emailAddress,
      user?.fullName || user?.username || undefined
    ),
    enabled: isClerkLoaded && !!user,
    retry: false,
  });

  if (!isClerkLoaded || isRoleLoading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-[#050505] text-white">
        <div className="w-12 h-12 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin mb-4"></div>
        <p className="text-gray-400 animate-pulse">Routing to Dashboard...</p>
      </div>
    );
  }

  if (roleData?.role === "admin") {
    return <Navigate to="/admin" replace />;
  }

  return <Navigate to="/user/analyser" replace />;
};

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/login" element={<Login />} />
          <Route path="/dashboard" element={<ProtectedRoute><DashboardRedirect /></ProtectedRoute>} />
          <Route path="/admin" element={<ProtectedRoute><AdminRoute><AdminDashboard /></AdminRoute></ProtectedRoute>} />
          <Route path="/admin/gateway" element={<ProtectedRoute><AdminRoute><AdminGateway /></AdminRoute></ProtectedRoute>} />
          <Route path="/user/analyser" element={<ProtectedRoute><UserAnalyser /></ProtectedRoute>} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
