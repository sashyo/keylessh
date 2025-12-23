import Stripe from 'stripe';
import type { SubscriptionTier } from '@shared/schema';

// Extended subscription type with period fields that may not be in newer Stripe type definitions
export type SubscriptionWithPeriod = Stripe.Subscription & {
  current_period_end?: number;
  current_period_start?: number;
};

// Initialize Stripe with secret key from environment
const stripeSecretKey = process.env.STRIPE_SECRET_KEY;

if (!stripeSecretKey) {
  console.warn('STRIPE_SECRET_KEY not set - Stripe functionality will be disabled');
}

export const stripe = stripeSecretKey
  ? new Stripe(stripeSecretKey, { apiVersion: '2025-12-15.clover' })
  : null;

// Price ID to tier mapping - configured via environment
const priceTierMap: Record<string, SubscriptionTier> = {};

export function initPriceTierMap() {
  const proPriceId = process.env.STRIPE_PRICE_ID_PRO;
  const enterprisePriceId = process.env.STRIPE_PRICE_ID_ENTERPRISE;

  if (proPriceId) priceTierMap[proPriceId] = 'pro';
  if (enterprisePriceId) priceTierMap[enterprisePriceId] = 'enterprise';
}

// Call on server startup
initPriceTierMap();

/**
 * Get tier from Stripe price ID
 */
export function getTierFromPriceId(priceId: string): SubscriptionTier {
  return priceTierMap[priceId] || 'free';
}

/**
 * Create a Stripe Checkout session for upgrading subscription
 */
export async function createCheckoutSession(params: {
  customerId?: string;
  customerEmail?: string;
  priceId: string;
  successUrl: string;
  cancelUrl: string;
  metadata?: Record<string, string>;
}): Promise<Stripe.Checkout.Session> {
  if (!stripe) {
    throw new Error('Stripe is not configured');
  }

  const sessionParams: Stripe.Checkout.SessionCreateParams = {
    mode: 'subscription',
    line_items: [{ price: params.priceId, quantity: 1 }],
    success_url: params.successUrl,
    cancel_url: params.cancelUrl,
    metadata: params.metadata,
    subscription_data: {
      metadata: params.metadata,
    },
  };

  // Use existing customer or create new one
  if (params.customerId) {
    sessionParams.customer = params.customerId;
  } else if (params.customerEmail) {
    sessionParams.customer_email = params.customerEmail;
  }

  return stripe.checkout.sessions.create(sessionParams);
}

/**
 * Create a Stripe Billing Portal session for managing subscription
 */
export async function createBillingPortalSession(
  customerId: string,
  returnUrl: string
): Promise<string> {
  if (!stripe) {
    throw new Error('Stripe is not configured');
  }

  const session = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: returnUrl,
  });

  return session.url;
}

/**
 * Get subscription details from Stripe
 */
export async function getSubscription(subscriptionId: string): Promise<SubscriptionWithPeriod> {
  if (!stripe) {
    throw new Error('Stripe is not configured');
  }

  return stripe.subscriptions.retrieve(subscriptionId) as Promise<SubscriptionWithPeriod>;
}

/**
 * Find a Stripe customer by email (best-effort).
 */
export async function findCustomerByEmail(email: string): Promise<Stripe.Customer | null> {
  if (!stripe) {
    throw new Error("Stripe is not configured");
  }

  const customers = await stripe.customers.list({ email, limit: 1 });
  return customers.data[0] ?? null;
}

/**
 * Get the most relevant subscription for a customer.
 * Prefers active/trialing/past_due subscriptions, otherwise returns the newest subscription if any.
 */
export async function findBestSubscriptionForCustomer(customerId: string): Promise<SubscriptionWithPeriod | null> {
  if (!stripe) {
    throw new Error("Stripe is not configured");
  }

  const subs = await stripe.subscriptions.list({
    customer: customerId,
    status: "all",
    limit: 10,
    expand: ["data.items.data.price"],
  });

  if (!subs.data.length) return null;

  const preferred = subs.data.find(
    (s) => s.status === "active" || s.status === "trialing" || s.status === "past_due",
  );
  return (preferred ?? subs.data[0] ?? null) as SubscriptionWithPeriod | null;
}

/**
 * Get Checkout session details from Stripe
 */
export async function getCheckoutSession(sessionId: string): Promise<Stripe.Checkout.Session> {
  if (!stripe) {
    throw new Error('Stripe is not configured');
  }

  return stripe.checkout.sessions.retrieve(sessionId, {
    expand: ["subscription", "customer"],
  });
}

/**
 * Construct and verify a Stripe webhook event
 */
export function constructWebhookEvent(
  payload: Buffer | string,
  signature: string
): Stripe.Event {
  if (!stripe) {
    throw new Error('Stripe is not configured');
  }

  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) {
    throw new Error('STRIPE_WEBHOOK_SECRET not configured');
  }

  return stripe.webhooks.constructEvent(payload, signature, webhookSecret);
}

/**
 * Check if Stripe is properly configured
 */
export function isStripeConfigured(): boolean {
  return stripe !== null;
}

/**
 * Get available price IDs from environment
 */
export function getAvailablePrices(): { pro?: string; enterprise?: string } {
  return {
    pro: process.env.STRIPE_PRICE_ID_PRO,
    enterprise: process.env.STRIPE_PRICE_ID_ENTERPRISE,
  };
}
