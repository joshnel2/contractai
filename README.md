# AI Contract Disputer and Analyzer

This is a subscription-based platform for analyzing contracts using Grok AI. Users get 20 queries per month for $9.99. Admin bypass with password "Tennis345!" at /admin.

## Setup Instructions

1. Create a GitHub repository and upload all files as structured below.
2. Set up environment variables (in your hosting service or locally):
   - STRIPE_SECRET_KEY: Your Stripe secret key.
   - STRIPE_PUBLISHABLE_KEY: Your Stripe publishable key.
   - STRIPE_WEBHOOK_SECRET: Your Stripe webhook secret.
   - GROK_API_KEY: Your Grok API key from x.ai/api.
   - Change DOMAIN in app.py to your deployed URL.
3. Install dependencies: `pip install -r requirements.txt`
4. Run locally: `python app.py`
5. For production, deploy to Heroku/Vercel/etc. and configure webhooks.

Note: Database is SQLite for MVP. Queries reset monthly.

Structure your repo like this:
- app.py
- requirements.txt
- templates/ (folder with HTML files)
