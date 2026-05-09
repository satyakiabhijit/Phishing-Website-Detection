import { motion, AnimatePresence } from "framer-motion";
import { useState, useEffect } from "react";

const STEPS = [
  "Normalizing URL structure...",
  "Querying threat intelligence APIs...",
  "Computing 21 lexical features...",
  "Running ML ensemble inference...",
  "Performing mathematical analysis...",
  "Fusing results for final verdict..."
];

export default function LoadingSteps({ isLoading }: { isLoading: boolean }) {
  const [currentStep, setCurrentStep] = useState(0);

  useEffect(() => {
    if (!isLoading) {
      setCurrentStep(0);
      return;
    }
    const interval = setInterval(() => {
      setCurrentStep((s) => (s + 1) % STEPS.length);
    }, 1500);
    return () => clearInterval(interval);
  }, [isLoading]);

  return (
    <AnimatePresence>
      {isLoading && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="mt-12 flex flex-col items-center"
        >
          <div className="w-12 h-12 border-4 border-accent-blue/20 border-t-accent-blue rounded-full animate-spin mb-4" />
          <p className="text-sm font-medium text-text-secondary animate-pulse">
            {STEPS[currentStep]}
          </p>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
