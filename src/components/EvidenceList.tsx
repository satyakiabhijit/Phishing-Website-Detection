import { motion } from "framer-motion";
import type { EvidenceItem } from "@/lib/types";

export default function EvidenceList({ items }: { items: EvidenceItem[] }) {
  if (items.length === 0) return null;

  return (
    <div className="space-y-4">
      <h3 className="text-xs uppercase tracking-widest font-bold text-text-muted ml-1">Threat Evidence</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {items.map((item, i) => (
          <motion.div
            key={item.id}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.5 + i * 0.1 }}
            className={`p-4 border rounded-2xl flex gap-4 ${
              item.severity === "critical" ? "bg-accent-red/5 border-accent-red/20" : 
              item.severity === "high" ? "bg-accent-amber/5 border-accent-amber/20" :
              "bg-bg-surface border-border"
            }`}
          >
            <div className="text-2xl mt-1">{item.icon}</div>
            <div>
              <h4 className="font-bold text-sm text-text-primary mb-1">{item.title}</h4>
              <p className="text-xs text-text-secondary leading-relaxed">{item.description}</p>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
