// ═══════════════════════════════════════════════════════════
// PhishGuard v2 — Whitelist & Trusted Domain Checks
// ═══════════════════════════════════════════════════════════

export const TRUSTED_SUFFIXES: string[] = [
  "vercel.app", "netlify.app", "supabase.co", "railway.app",
  "render.com", "fly.dev", "github.io", "pages.dev",
  "cloudflare.com", "amazonaws.com", "azurewebsites.net",
  "googleusercontent.com", "herokuapp.com", "onrender.com",
  "workers.dev", "deno.dev", "replit.dev", "glitch.me",
];

export const TECH_BRAND_BYPASS: string[] = [
  "supabase", "prisma", "planetscale", "neon", "turso", "drizzle",
  "vercel", "netlify", "railway", "render", "deno", "bun",
  "svelte", "nuxt", "astro", "remix", "vite", "webpack",
  "kubernetes", "terraform", "grafana", "prometheus", "datadog",
  "sentry", "posthog", "mixpanel", "amplitude",
  "stripe", "plaid", "twilio", "sendgrid", "resend",
  "clerk", "auth0", "okta", "stytch",
  "huggingface", "langchain", "pinecone", "weaviate",
  "figma", "canva", "miro", "notion", "linear",
  "shopify", "squarespace", "webflow", "framer",
  "openai", "anthropic", "cohere", "mistral",
];

export const TRUSTED_SUBDOMAIN_TLDS: string[] = [
  "vercel.app", "pages.dev", "netlify.app", "herokuapp.com",
  "onrender.com", "azurewebsites.net", "cloudfront.net",
  "github.io", "workers.dev",
];

export function isTrustedDomain(domain: string): boolean {
  const d = domain.toLowerCase();
  return TRUSTED_SUFFIXES.some((suffix) => d.endsWith(suffix));
}

export function isTechBrand(domainName: string): boolean {
  return TECH_BRAND_BYPASS.includes(domainName.toLowerCase());
}

export function isTrustedSubdomainTLD(domain: string): boolean {
  const d = domain.toLowerCase();
  return TRUSTED_SUBDOMAIN_TLDS.some((suffix) => d.endsWith(suffix));
}

export const TRUSTED_DOMAIN_BONUS = 0.15;
