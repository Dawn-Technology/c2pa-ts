/**
 * JWK DID Resolver
 * Resolves Decentralized Identifiers (DIDs) using the did:jwk method
 *
 * Implements DID resolution for the `did:jwk` method as specified in the
 * DID JWK specification. This method allows encoding a JSON Web Key directly
 * in the DID identifier.
 *
 * @module cawg/jwk-did-resolver
 */
import type {
    DIDResolutionOptions,
    DIDResolutionResult,
    DIDResolver,
    JsonWebKey as DidResolverJsonWebKey,
    ParsedDID,
    Resolvable,
} from 'did-resolver';
import { base64ToBytes } from './utils';

/** DID method name for JWK-based DIDs */
const DID_JWK_METHOD = 'jwk';
/** Content type for DID resolution results */
const DID_JWK_CONTENT_TYPE = 'application/did+ld+json';

/**
 * Decodes a base64url-encoded string to bytes
 * @param input - Base64url-encoded string (padding may be omitted)
 * @returns Decoded byte array
 * @internal
 */
function decodeBase64Url(input: string): Uint8Array {
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    const padding = normalized.length % 4;
    const padded = padding === 0 ? normalized : `${normalized}${'='.repeat(4 - padding)}`;

    return base64ToBytes(padded);
}

/**
 * Creates a DID resolution error result
 * @param error - Error message describing the resolution failure
 * @returns DID resolution result with error metadata
 * @internal
 */
function invalidDidResult(error: string): DIDResolutionResult {
    return {
        didResolutionMetadata: { error },
        didDocument: null,
        didDocumentMetadata: {},
    };
}

/**
 * Type guard to verify if a value is a valid JsonWebKey
 * @param value - Value to check
 * @returns True if value is a valid JsonWebKey with kty property
 * @internal
 */
function isDidResolverJsonWebKey(value: unknown): value is DidResolverJsonWebKey {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return false;
    }

    const candidate = value as { kty?: unknown };
    return typeof candidate.kty === 'string';
}

/**
 * Parses a did:jwk DID and extracts the embedded JSON Web Key
 * @param _did - The full DID string (unused but part of resolver signature)
 * @param parsed - Parsed DID components
 * @returns Extracted JsonWebKey or null if parsing fails
 * @internal
 */
function parseDidJwk(_did: string, parsed: ParsedDID): DidResolverJsonWebKey | null {
    if (parsed.method !== DID_JWK_METHOD || !parsed.id) {
        return null;
    }

    try {
        const payloadBytes = decodeBase64Url(parsed.id);
        const payloadJson = new TextDecoder().decode(payloadBytes);
        const payload: unknown = JSON.parse(payloadJson);

        if (!isDidResolverJsonWebKey(payload)) {
            return null;
        }

        return payload;
    } catch {
        return null;
    }
}

/**
 * DID resolver implementation for the `did:jwk` method
 *
 * Resolves a did:jwk DID to a DID document containing the embedded public key
 * as a JsonWebKey2020 verification method.
 *
 * @param did - The complete DID to resolve
 * @param parsed - Pre-parsed DID components
 * @param _resolver - The parent resolver (unused)
 * @param _options - Resolution options (unused)
 * @returns Promise resolving to DID resolution result
 * @internal
 */
const jwkResolver: DIDResolver = (
    did: string,
    parsed: ParsedDID,
    _resolver: Resolvable,
    _options: DIDResolutionOptions,
): Promise<DIDResolutionResult> => {
    const publicKeyJwk = parseDidJwk(did, parsed);
    if (!publicKeyJwk) {
        return Promise.resolve(invalidDidResult('invalidDid'));
    }

    const verificationMethodId = `${did}#0`;

    return Promise.resolve({
        didResolutionMetadata: {
            contentType: DID_JWK_CONTENT_TYPE,
        },
        didDocument: {
            id: did,
            verificationMethod: [
                {
                    id: verificationMethodId,
                    type: 'JsonWebKey2020',
                    controller: did,
                    publicKeyJwk,
                },
            ],
            assertionMethod: [verificationMethodId],
        },
        didDocumentMetadata: {},
    });
};

/**
 * Returns a resolver registry entry for the `did:jwk` method
 *
 * Compatible with `did-resolver`'s `Resolver` constructor.
 * This function should be spread into the resolver configuration object.
 *
 * @returns Object containing the jwk method resolver
 *
 * @example
 * ```ts
 * import { Resolver } from 'did-resolver';
 * import { getResolver } from './jwk-did-resolver';
 *
 * const resolver = new Resolver({ ...getResolver() });
 * const result = await resolver.resolve('did:jwk:...');
 * ```
 */
export function getResolver(): { jwk: DIDResolver } {
    return { jwk: jwkResolver };
}
