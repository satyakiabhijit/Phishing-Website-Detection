"use client";
import { useState } from "react";
import { motion } from "framer-motion";

interface Props {
  onSubmit: (url: string) => void;
  isLoading: boolean;
}

export default function UrlInput({ onSubmit, isLoading }: Props) {
  const [url, setUrl] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url && !isLoading) onSubmit(url);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl px-4">
      <div className="relative group">
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Enter URL to scan (e.g. apple-verify.security-check.com)"
          className="w-full h-14 bg-bg-surface border border-border rounded-2xl px-6 pr-32 text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-blue/50 transition-all shadow-lg group-hover:border-border-hover"
        />
        <button
          disabled={isLoading || !url}
          className="absolute right-2 top-2 h-10 px-6 bg-accent-blue text-white rounded-xl font-medium hover:bg-accent-blue/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        >
          {isLoading ? "Scanning..." : "Scan URL"}
        </button>
      </div>
    </form>
  );
}
