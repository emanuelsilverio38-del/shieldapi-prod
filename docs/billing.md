# Billing

Billing is handled through Stripe Checkout and Stripe webhooks.

Main routes:

- `GET|POST /billing/create-checkout-session`
- `POST /billing/portal`
- `GET /billing/success`
- `GET /billing/cancel`
- `POST /webhooks/stripe`

After successful checkout, ShieldAPI creates or updates the API client and delivers a generated API key once through `/billing/success`.
