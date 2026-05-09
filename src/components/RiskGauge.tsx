export default function RiskGauge({ score }: { score: number }) {
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score * circumference);
  
  const color = score > 0.8 ? "#ef4444" : score > 0.5 ? "#f59e0b" : "#22c55e";

  return (
    <div className="relative w-32 h-32 flex items-center justify-center">
      <svg className="w-full h-full transform -rotate-90">
        <circle
          cx="64" cy="64" r={radius}
          stroke="currentColor" strokeWidth="8" fill="transparent"
          className="text-border"
        />
        <circle
          cx="64" cy="64" r={radius}
          stroke={color} strokeWidth="8" fill="transparent"
          strokeDasharray={circumference}
          style={{ strokeDashoffset: offset, transition: "stroke-dashoffset 1.5s ease-out" }}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-black text-text-primary">{(score * 100).toFixed(0)}</span>
        <span className="text-[10px] uppercase font-bold text-text-muted">Risk</span>
      </div>
    </div>
  );
}
