/**
 * DID Resolver Configuration
 * Configures the DID resolver with support for CAWG-supported DID methods
 *
 * Supports resolution for:
 * - did:web
 * - did:jwk
 * - did:key
 *
 * @module cawg/did-resolver
 */
import { Resolver } from 'did-resolver';
import { getResolver as keyResolver } from 'key-did-resolver';
import { getResolver as webResolver } from 'web-did-resolver';
import { getResolver as jwkResolver } from './jwk-did-resolver';

/**
 * Shared DID resolver instance used by CAWG validators
 *
 * This resolver is used to resolve issuer DIDs to DID documents so the
 * corresponding verification keys can be extracted for signature validation.
 */
export const didResolver = new Resolver({
    ...webResolver(),
    ...jwkResolver(),
    ...keyResolver(),
});
