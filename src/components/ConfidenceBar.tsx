import { motion } from "framer-motion";

export default function ConfidenceBar({ value }: { value: number }) {
  return (
    <div className="w-full bg-bg-surface border border-border rounded-2xl p-4">
      <div className="flex justify-between text-xs mb-2">
        <span className="text-text-secondary">Analysis Confidence</span>
        <span className="font-bold text-text-primary">{(value * 100).toFixed(0)}%</span>
      </div>
      <div className="h-2 bg-bg-elevated rounded-full overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${value * 100}%` }}
          transition={{ duration: 1, ease: "easeOut" }}
          className="h-full bg-accent-blue shadow-[0_0_10px_rgba(59,130,246,0.5)]"
        />
      </div>
    </div>
  );
}
