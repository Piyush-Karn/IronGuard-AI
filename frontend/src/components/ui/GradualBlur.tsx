const GradualBlur = () => (
  <div className="absolute inset-0 pointer-events-none z-[1]">
    {/* Top blur layer */}
    <div className="absolute top-0 left-0 right-0 h-40 bg-gradient-to-b from-black via-black/80 to-transparent backdrop-blur-[1px]" />
    {/* Bottom blur layer */}
    <div className="absolute bottom-0 left-0 right-0 h-40 bg-gradient-to-t from-black via-black/80 to-transparent backdrop-blur-[1px]" />
    {/* Mid-section soft depth layers */}
    <div className="absolute top-1/4 left-0 right-0 h-32 bg-gradient-to-b from-transparent via-black/[0.15] to-transparent" />
    <div className="absolute top-2/3 left-0 right-0 h-32 bg-gradient-to-b from-transparent via-black/[0.1] to-transparent" />
  </div>
);

export default GradualBlur;
