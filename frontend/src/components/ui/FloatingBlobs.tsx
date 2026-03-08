const FloatingBlobs = () => (
  <div className="absolute inset-0 overflow-hidden pointer-events-none">
    <div className="absolute -top-32 -left-32 w-96 h-96 rounded-full bg-purple-500/[0.04] blur-[120px] animate-[pulse_8s_ease-in-out_infinite]" />
    <div className="absolute top-1/3 -right-20 w-80 h-80 rounded-full bg-blue-500/[0.04] blur-[100px] animate-[pulse_10s_ease-in-out_infinite_2s]" />
    <div className="absolute -bottom-20 left-1/3 w-72 h-72 rounded-full bg-indigo-500/[0.03] blur-[100px] animate-[pulse_12s_ease-in-out_infinite_4s]" />
  </div>
);

export default FloatingBlobs;
