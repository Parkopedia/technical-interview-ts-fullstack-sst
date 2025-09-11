# SST App

This is a [SST](https://sst.dev/) project bootstrapped with `create-sst`.

## Prerequisites

- [Node.js](https://nodejs.org/en/download/) (20.x or newer)
- [AWS Account](https://aws.amazon.com/) (`technical-interviews` profile)
- [Stripe Account](https://stripe.com/)

## Configure

```
# AWS
aws configure set region eu-central-1 --profile technical-interviews && \
aws configure set aws_access_key_id "xxx" --profile technical-interviews && \
aws configure set aws_secret_access_key "xxx" --profile technical-interviews

# Stripe API key
npx sst secrets set STRIPE_KEY sk_test_abc123
```

## Quickstart

```bash
# Install dependencies
npm install

# Run development environment
npm run dev

✔  Deployed:
   API
   ApiUrl: https://xxx.execute-api.eu-central-1.amazonaws.com

# Request customer portal URL
curl "https://xxx.execute-api.eu-central-1.amazonaws.com/drivers/1/get-customer-portal-url"
```
