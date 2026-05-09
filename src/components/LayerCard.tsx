import { motion } from "framer-motion";

interface Props {
  title: string;
  icon: string;
  score: number;
  weight: number;
  status: "available" | "unavailable";
  details: string[];
  index: number;
}

export default function LayerCard({ title, icon, score, weight, status, details, index }: Props) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1 }}
      className="bg-bg-surface border border-border rounded-2xl p-5 hover:border-border-hover transition-all"
    >
      <div className="flex justify-between items-start mb-4">
        <div className="flex items-center gap-3">
          <span className="text-2xl">{icon}</span>
          <div>
            <h3 className="font-bold text-text-primary leading-none">{title}</h3>
            <span className="text-[10px] text-text-muted uppercase tracking-wider">Weight: {(weight * 100).toFixed(0)}%</span>
          </div>
        </div>
        <div className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
          status === "available" ? "bg-accent-green/10 text-accent-green" : "bg-text-muted/10 text-text-muted"
        }`}>
          {status}
        </div>
      </div>
      
      <div className="mb-4">
        <div className="flex justify-between text-xs mb-1">
          <span className="text-text-secondary">Risk Score</span>
          <span className="font-mono text-text-primary">{(score * 100).toFixed(1)}%</span>
        </div>
        <div className="h-1.5 bg-bg-elevated rounded-full overflow-hidden">
          <div 
            className={`h-full transition-all duration-1000 ${score > 0.7 ? 'bg-accent-red' : score > 0.4 ? 'bg-accent-amber' : 'bg-accent-green'}`}
            style={{ width: `${score * 100}%` }}
          />
        </div>
      </div>

      <div className="space-y-1.5">
        {details.map((d, i) => (
          <p key={i} className="text-[11px] text-text-muted flex items-start gap-2">
            <span className="mt-1 w-1 h-1 rounded-full bg-border" />
            {d}
          </p>
        ))}
      </div>
    </motion.div>
  );
}
