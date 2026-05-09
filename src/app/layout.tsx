import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "@/styles/globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-geist-sans",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-geist-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "PhishGuard — AI Phishing Detection",
  description:
    "4-layer AI phishing detection platform. Analyzes URLs across 95+ threat engines, ML ensemble, and mathematical models for real-time verdicts.",
  keywords: ["phishing", "security", "URL scanner", "threat detection", "AI"],
  authors: [{ name: "PhishGuard" }],
  openGraph: {
    title: "PhishGuard — Is this URL safe?",
    description: "4-layer AI analysis across 95+ threat engines",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased`}
      >
        <div className="relative z-10 min-h-screen">{children}</div>
      </body>
    </html>
  );
}
