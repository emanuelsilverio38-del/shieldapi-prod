// src/routes/docs.js

export function handleDocs(req, res, context = {}) {
  const docs = {
    name: "ShieldAPI",
    version: "4.7",
    description:
      "Security and intelligence API for Solana AI agents, trading bots and token scanners.",
    status: "online",

    endpoints: {
      public: [
        {
          method: "GET",
          path: "/health",
          description: "API health check"
        },
        {
          method: "GET",
          path: "/docs",
          description: "API documentation"
        },
        {
          method: "GET",
          path: "/cache/stats",
          description: "Memory and persistent cache statistics"
        },
        {
          method: "GET",
          path: "/billing/cancel",
          description: "Stripe billing cancel page"
        }
      ],

      authenticated: [
        {
          method: "GET",
          path: "/usage",
          description: "Shows client plan, quota and usage"
        },
        {
          method: "GET",
          path: "/analyze?address=TOKEN_MINT",
          description: "Analyze a Solana token"
        },
        {
          method: "GET",
          path: "/analyze-fast?address=TOKEN_MINT",
          description: "Fast token analysis using memory and PostgreSQL cache"
        },
        {
          method: "POST",
          path: "/submit",
          description: "Submit token for analysis/cache"
        }
      ],

      billing: [
        {
          method: "POST",
          path: "/billing/create-checkout-session",
          description: "Create Stripe Checkout session"
        },
        {
          method: "GET",
          path: "/billing/success",
          description: "Stripe payment success page"
        },
        {
          method: "POST",
          path: "/billing/portal",
          description: "Create Stripe customer portal session"
        },
        {
          method: "POST",
          path: "/webhooks/stripe",
          description: "Stripe webhook endpoint"
        }
      ],

      admin: [
        {
          method: "POST",
          path: "/admin/clients/create",
          description: "Create API client manually"
        },
        {
          method: "GET",
          path: "/admin/clients",
          description: "List API clients"
        },
        {
          method: "POST",
          path: "/admin/clients/disable",
          description: "Disable API client"
        },
        {
          method: "GET",
          path: "/admin/clients/usage",
          description: "View usage by client"
        }
      ]
    },

    plans: {
      Free: {
        quota: "100 requests/day",
        rateLimit: "30/min"
      },
      Starter: {
        quota: "10,000 requests/month",
        rateLimit: "120/min"
      },
      Pro: {
        quota: "100,000 requests/month",
        rateLimit: "600/min"
      },
      Advanced: {
        quota: "500,000 requests/month",
        rateLimit: "1500/min"
      },
      Enterprise: {
        quota: "custom",
        rateLimit: "custom"
      }
    },

    roadmap: {
      current: "ShieldAPI v4.7 SaaS layer",
      next: "ShieldAPI v4.8 Security Module Pro",
      plannedModules: [
        "RugCheck",
        "Solana token authorities",
        "Holders concentration",
        "Liquidity risk",
        "Creator risk",
        "Scanner module",
        "Jupiter quote module",
        "Jito integration",
        "Client/Admin dashboard"
      ]
    },

    securityNotes: [
      "Authenticated endpoints require an API key.",
      "The current analysis engine is mainly Dexscreener-based.",
      "ShieldAPI v4.8 will add deeper Solana security intelligence.",
      "Execution modules are not active yet.",
      "ShieldAPI does not custody private keys."
    ]
  };

  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(docs, null, 2));

  return true;
}