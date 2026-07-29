// FP guard: generic assignment patterns capture whatever follows `:` / `=`.
// In real code that is very often a reference to another variable, not a
// literal credential. Found by scanning real repositories during the 1.4.0
// audit; none of these lines contains a secret.

const scheduledIngestApiKey = loadFromVault();
const externalBillingServiceKey = loadFromVault();
const internalSigningSecret = loadFromVault();
const defaultServiceCredential = loadFromVault();

export async function postSmokeEvent(body: unknown) {
  return fetch('https://example.internal/ingest', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': scheduledIngestApiKey,
    },
    body: JSON.stringify(body),
  });
}

export const billingClient = {
  apiKey: externalBillingServiceKey,
  secret: internalSigningSecret,
};

export function buildAuthConfig() {
  const api_key = defaultServiceCredential;
  return { api_key };
}

declare function loadFromVault(): string;
