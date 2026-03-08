const AuroraBackground = () => {
  return (
    <div className="absolute inset-0 overflow-hidden">
      <div
        className="absolute -top-1/2 -left-1/2 w-[200%] h-[200%] animate-spin"
        style={{
          background:
            "conic-gradient(from 0deg, transparent 0%, rgba(120,119,198,0.08) 25%, transparent 50%, rgba(120,119,198,0.05) 75%, transparent 100%)",
          animationDuration: "20s",
        }}
      />
      <div
        className="absolute -top-1/2 -left-1/2 w-[200%] h-[200%] animate-spin"
        style={{
          background:
            "conic-gradient(from 180deg, transparent 0%, rgba(59,130,246,0.06) 25%, transparent 50%, rgba(59,130,246,0.04) 75%, transparent 100%)",
          animationDuration: "15s",
          animationDirection: "reverse",
        }}
      />
    </div>
  );
};

export default AuroraBackground;
