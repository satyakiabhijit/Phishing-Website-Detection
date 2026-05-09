import { motion } from "framer-motion";

interface Props {
  verdict: string;
  score: number;
  confidence: number;
}

export default function VerdictBadge({ verdict, score, confidence }: Props) {
  const isPhish = verdict === "Phishing";
  const isSafe = verdict === "Legitimate";
  
  const colors = isPhish 
    ? "bg-accent-red/10 text-accent-red border-accent-red/20" 
    : isSafe 
    ? "bg-accent-green/10 text-accent-green border-accent-green/20"
    : "bg-accent-amber/10 text-accent-amber border-accent-amber/20";

  return (
    <motion.div
      initial={{ scale: 0.9, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      className={`p-6 border rounded-3xl ${colors} flex flex-col items-center text-center`}
    >
      <span className="text-xs uppercase tracking-widest font-bold opacity-70 mb-2">Verdict</span>
      <h2 className="text-4xl font-black mb-1">{verdict}</h2>
      <p className="text-sm opacity-80">
        Score: {(score * 100).toFixed(1)}% | Confidence: {(confidence * 100).toFixed(0)}%
      </p>
    </motion.div>
  );
}
