import { env } from '../config/env.js';
import { getStripeClient } from './stripeClient.js';
import { generateClientApiKey } from '../auth/apiKeys.js';
import { getPlanByStripePriceId, normalizePlan } from '../auth/plans.js';
import {
  createClient,
  findClientByStripeCustomerId,
  findClientByStripeSubscriptionId,
  updateClientBilling,
} from '../db/clientsRepository.js';
import { storeApiKeyDelivery } from './apiKeyDelivery.js';

function unixToIso(value) {
  if (!value) return null;
  return new Date(Number(value) * 1000).toISOString();
}

function getSubscriptionPlan(subscription) {
  const priceId = subscription?.items?.data?.[0]?.price?.id || null;
  return getPlanByStripePriceId(priceId) || normalizePlan(subscription?.metadata?.plan || 'starter');
}

function getSessionPlan(session) {
  return normalizePlan(session?.metadata?.plan || 'starter');
}

function getCustomerEmailFromSession(session) {
  return (
    session?.customer_details?.email ||
    session?.customer_email ||
    null
  );
}

export function constructStripeWebhookEvent(rawBody, signature) {
  const stripe = getStripeClient();

  if (!stripe) {
    throw new Error('Stripe is not configured');
  }

  if (!env.STRIPE_WEBHOOK_SECRET) {
    throw new Error('Stripe webhook secret is not configured');
  }

  return stripe.webhooks.constructEvent(
    rawBody,
    signature,
    env.STRIPE_WEBHOOK_SECRET
  );
}

export async function handleCheckoutSessionCompleted(pool, session) {
  if (!pool) {
    throw new Error('Database pool is required');
  }

  const stripe = getStripeClient();
  const stripeCustomerId = typeof session.customer === 'string'
    ? session.customer
    : session.customer?.id;

  const stripeSubscriptionId = typeof session.subscription === 'string'
    ? session.subscription
    : session.subscription?.id;

  const email = getCustomerEmailFromSession(session);
  let plan = getSessionPlan(session);
  let currentPeriodStart = null;
  let currentPeriodEnd = null;

  if (stripe && stripeSubscriptionId) {
    try {
      const subscription = await stripe.subscriptions.retrieve(stripeSubscriptionId);
      plan = getSubscriptionPlan(subscription);
      currentPeriodStart = unixToIso(subscription.current_period_start);
      currentPeriodEnd = unixToIso(subscription.current_period_end);
    } catch (error) {
      console.warn('[Stripe webhook] Failed to retrieve subscription:', error.message);
    }
  }

  const existingBySubscription = stripeSubscriptionId
    ? await findClientByStripeSubscriptionId(pool, stripeSubscriptionId)
    : null;

  if (existingBySubscription) {
    const updated = await updateClientBilling(pool, {
      clientId: existingBySubscription.id,
      stripeCustomerId,
      stripeSubscriptionId,
      plan,
      billingStatus: 'active',
      status: 'active',
      currentPeriodStart,
      currentPeriodEnd,
    });

    return {
      action: 'updated_existing_subscription_client',
      client: updated,
      apiKey: null,
    };
  }

  const existingByCustomer = stripeCustomerId
    ? await findClientByStripeCustomerId(pool, stripeCustomerId)
    : null;

  if (existingByCustomer) {
    const updated = await updateClientBilling(pool, {
      clientId: existingByCustomer.id,
      stripeCustomerId,
      stripeSubscriptionId,
      plan,
      billingStatus: 'active',
      status: 'active',
      currentPeriodStart,
      currentPeriodEnd,
    });

    return {
      action: 'updated_existing_customer_client',
      client: updated,
      apiKey: null,
    };
  }

  const apiKey = generateClientApiKey();
  const clientName = email || `stripe_customer_${stripeCustomerId || Date.now()}`;

  const client = await createClient(pool, {
    name: clientName,
    email,
    apiKey,
    plan,
    stripeCustomerId,
    stripeSubscriptionId,
    billingStatus: 'active',
    status: 'active',
    metadata: {
      createdBy: 'stripe_webhook',
      checkoutSessionId: session.id,
    },
  });

  if (currentPeriodStart || currentPeriodEnd) {
    await updateClientBilling(pool, {
      clientId: client.id,
      currentPeriodStart,
      currentPeriodEnd,
    });
  }

  await storeApiKeyDelivery(pool, {
    sessionId: session.id,
    clientId: client.id,
    apiKey,
  });

  return {
    action: 'created_new_client',
    client,
    apiKey,
  };
}

export async function handleSubscriptionUpdated(pool, subscription) {
  if (!pool) {
    throw new Error('Database pool is required');
  }

  const stripeCustomerId = typeof subscription.customer === 'string'
    ? subscription.customer
    : subscription.customer?.id;

  const stripeSubscriptionId = subscription.id;
  const plan = getSubscriptionPlan(subscription);

  const billingStatus = subscription.status || 'unknown';
  const isActive = ['active', 'trialing'].includes(billingStatus);

  const updated = await updateClientBilling(pool, {
    stripeSubscriptionId,
    stripeCustomerId,
    plan,
    billingStatus,
    status: isActive ? 'active' : 'disabled',
    currentPeriodStart: unixToIso(subscription.current_period_start),
    currentPeriodEnd: unixToIso(subscription.current_period_end),
  });

  return {
    action: 'subscription_updated',
    client: updated,
    plan,
    billingStatus,
  };
}

export async function handleSubscriptionDeleted(pool, subscription) {
  if (!pool) {
    throw new Error('Database pool is required');
  }

  const stripeCustomerId = typeof subscription.customer === 'string'
    ? subscription.customer
    : subscription.customer?.id;

  const stripeSubscriptionId = subscription.id;

  const updated = await updateClientBilling(pool, {
    stripeSubscriptionId,
    stripeCustomerId,
    billingStatus: 'canceled',
    status: 'disabled',
    currentPeriodStart: unixToIso(subscription.current_period_start),
    currentPeriodEnd: unixToIso(subscription.current_period_end),
  });

  return {
    action: 'subscription_deleted',
    client: updated,
  };
}

export async function handleInvoicePaymentFailed(pool, invoice) {
  if (!pool) {
    throw new Error('Database pool is required');
  }

  const stripeCustomerId = typeof invoice.customer === 'string'
    ? invoice.customer
    : invoice.customer?.id;

  const stripeSubscriptionId = typeof invoice.subscription === 'string'
    ? invoice.subscription
    : invoice.subscription?.id;

  const updated = await updateClientBilling(pool, {
    stripeSubscriptionId,
    stripeCustomerId,
    billingStatus: 'payment_failed',
    status: 'disabled',
  });

  return {
    action: 'invoice_payment_failed',
    client: updated,
  };
}

export async function handleStripeWebhookEvent(pool, event) {
  if (!event?.type) {
    return {
      handled: false,
      reason: 'missing_event_type',
    };
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const result = await handleCheckoutSessionCompleted(pool, event.data.object);
      return {
        handled: true,
        eventType: event.type,
        ...result,
      };
    }

    case 'customer.subscription.updated': {
      const result = await handleSubscriptionUpdated(pool, event.data.object);
      return {
        handled: true,
        eventType: event.type,
        ...result,
      };
    }

    case 'customer.subscription.deleted': {
      const result = await handleSubscriptionDeleted(pool, event.data.object);
      return {
        handled: true,
        eventType: event.type,
        ...result,
      };
    }

    case 'invoice.payment_failed': {
      const result = await handleInvoicePaymentFailed(pool, event.data.object);
      return {
        handled: true,
        eventType: event.type,
        ...result,
      };
    }

    default:
      return {
        handled: false,
        eventType: event.type,
        reason: 'unsupported_event_type',
      };
  }
}
