/**
 * CAWG Identity Assertion Utilities
 * Helper functions for CBOR serialization, hashing, and data transformation
 *
 * @module cawg/utils
 */
import * as cborX from 'cbor-x';
import { Crypto, HashAlgorithm } from '../crypto';
import { Claim } from '../manifest/Claim';
import type { C2paAssetBinding, HashedUriMap, HashMap, SignerPayloadMap } from './types.js';

/**
 * Serialize claim data using CBOR deterministic encoding
 *
 * @param payload - The claim data to serialize
 * @returns CBOR-encoded claim bytes
 */
export function serializeClaimData(payload: Claim): Uint8Array {
    // Use deterministic encoding for consistent results
    return cborX.encode(payload);
}

/**
 * Validate that padding contains only zero (0x00) bytes
 *
 * @param pad - The padding bytes to validate
 * @returns True if all bytes are 0x00, false otherwise
 */
export function validatePadding(pad: Uint8Array): boolean {
    return pad.every(byte => byte === 0x00);
}

/**
 * Convert byte array to base64 string
 *
 * Uses Node.js Buffer if available, otherwise falls back to btoa().
 *
 * @param bytes - The bytes to encode
 * @returns Base64-encoded string
 * @throws Error if no base64 encoder is available in this runtime
 */
export function bytesToBase64(bytes: Uint8Array): string {
    const bufferCtor = (globalThis as { Buffer?: typeof Buffer }).Buffer;
    if (bufferCtor?.from) {
        return bufferCtor.from(bytes).toString('base64');
    }
    if (typeof globalThis.btoa === 'function') {
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return globalThis.btoa(binary);
    }
    throw new Error('No base64 encoder available in this runtime');
}

/**
 * Convert base64 string to byte array
 *
 * Handles Node.js Buffer or browser atob APIs depending on runtime environment.
 * Accepts strings, Uint8Array, or number arrays.
 *
 * @param base64 - Base64-encoded string, bytes, or number array
 * @returns Decoded byte array
 * @throws Error if no base64 decoder is available in this runtime
 */
export function base64ToBytes(base64: string | Uint8Array | number[]): Uint8Array {
    // If input is already a number array, convert directly to Uint8Array
    let base64String: string;
    if (Array.isArray(base64)) {
        base64String = new TextDecoder().decode(new Uint8Array(base64));
    } else if (base64 instanceof Uint8Array) {
        base64String = new TextDecoder().decode(base64);
    } else {
        base64String = base64;
    }

    const bufferCtor = (globalThis as { Buffer?: typeof Buffer }).Buffer;
    if (bufferCtor?.from) {
        return new Uint8Array(bufferCtor.from(base64String, 'base64'));
    }

    if (typeof globalThis.atob === 'function') {
        const binary = globalThis.atob(base64String);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    throw new Error('No base64 decoder available in this runtime');
}

/**
 * Convert byte array to base64url string
 *
 * Uses RFC 4648 base64url encoding (URL-safe variant without padding).
 *
 * @param bytes - The bytes to encode
 * @returns Base64url-encoded string (without padding)
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
    return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/**
 * Convert signer_payload to C2PA asset binding format for verifiable credentials
 *
 * Transforms the CBOR binary signer_payload into JSON-friendly format by
 * converting byte hashes to base64 strings for use in ICA credentials.
 *
 * @param payload - The signer payload to convert
 * @returns C2PA asset binding in JSON-compatible format
 */
export function signerPayloadToC2paAssetBinding(payload: SignerPayloadMap): C2paAssetBinding {
    return {
        referenced_assertions: payload.referenced_assertions.map(ra => ({
            url: ra.url,
            ...(ra.alg && { alg: ra.alg }),
            hash: bytesToBase64(ra.hash),
        })),
        sig_type: payload.sig_type,
        ...(payload.role && { role: payload.role }),
        ...(payload.expected_partial_claim && {
            expected_partial_claim: {
                alg: payload.expected_partial_claim.alg,
                hash: bytesToBase64(payload.expected_partial_claim.hash),
            },
        }),
        ...(payload.expected_claim_generator && {
            expected_claim_generator: {
                alg: payload.expected_claim_generator.alg,
                hash: bytesToBase64(payload.expected_claim_generator.hash),
            },
        }),
        ...(payload.expected_countersigners && {
            expected_countersigners: payload.expected_countersigners.map(ec => ({
                partial_signer_payload: signerPayloadToC2paAssetBinding(ec.partial_signer_payload),
                ...(ec.expected_credentials && {
                    expected_credentials: {
                        alg: ec.expected_credentials.alg,
                        hash: bytesToBase64(ec.expected_credentials.hash),
                    },
                }),
            })),
        }),
    };
}

/**
 * Convert C2PA asset binding to signer_payload format
 *
 * Transforms JSON-format C2PA asset binding (from ICA credentials) back to
 * the CBOR-compatible signer_payload format by decoding base64 hashes to bytes.
 *
 * @param binding - The C2PA asset binding to convert
 * @returns Signer payload in CBOR-compatible format
 */
export function c2paAssetBindingToSignerPayload(binding: C2paAssetBinding): SignerPayloadMap {
    return {
        referenced_assertions: binding.referenced_assertions.map(ra => ({
            url: ra.url,
            ...(ra.alg && { alg: ra.alg }),
            hash: base64ToBytes(ra.hash),
        })),
        sig_type: binding.sig_type,
        ...(binding.role && { role: binding.role }),
        ...(binding.expected_partial_claim && {
            expected_partial_claim: {
                alg: binding.expected_partial_claim.alg,
                hash: base64ToBytes(binding.expected_partial_claim.hash),
            },
        }),
        ...(binding.expected_claim_generator && {
            expected_claim_generator: {
                alg: binding.expected_claim_generator.alg,
                hash: base64ToBytes(binding.expected_claim_generator.hash),
            },
        }),
        ...(binding.expected_countersigners && {
            expected_countersigners: binding.expected_countersigners.map(ec => ({
                partial_signer_payload: c2paAssetBindingToSignerPayload(ec.partial_signer_payload),
                ...(ec.expected_credentials && {
                    expected_credentials: {
                        alg: ec.expected_credentials.alg,
                        hash: base64ToBytes(ec.expected_credentials.hash),
                    },
                }),
            })),
        }),
    };
}

/**
 * Check if two hash maps are equal
 *
 * Compares hash maps by algorithm and hash value.
 *
 * @param a - First hash map
 * @param b - Second hash map
 * @returns True if both maps are equal
 */
export function hashMapsEqual(a: HashMap, b: HashMap): boolean {
    if (a.alg !== b.alg) return false;
    if (a.hash.length !== b.hash.length) return false;
    return a.hash.every((byte, i) => byte === b.hash[i]);
}

/**
 * Check if two hashed URI maps are equal
 *
 * Compares hashed URI maps by URL, algorithm, and hash value.
 *
 * @param a - First hashed URI map
 * @param b - Second hashed URI map
 * @returns True if both maps are equal
 */
export function hashedUriMapsEqual(a: HashedUriMap, b: HashedUriMap): boolean {
    if (a.url !== b.url) return false;
    if (a.alg !== b.alg) return false;
    if (a.hash.length !== b.hash.length) return false;
    return a.hash.every((byte, i) => byte === b.hash[i]);
}

/**
 * Find duplicates in an array of hashed URI maps
 *
 * Identifies hashed URI references that appear multiple times in the array.
 *
 * @param references - Array of hashed URI maps to check
 * @returns Array of duplicate references (excluding first occurrence)
 */
export function findDuplicateReferences(references: HashedUriMap[]): HashedUriMap[] {
    const seen = new Set<string>();
    const duplicates: HashedUriMap[] = [];

    for (const ref of references) {
        const key = `${ref.url}:${ref.alg}:${bytesToBase64(ref.hash)}`;
        if (seen.has(key)) {
            duplicates.push(ref);
        } else {
            seen.add(key);
        }
    }

    return duplicates;
}

/**
 * Check if an assertion is a hard binding assertion
 *
 * Hard binding assertions are C2PA hash assertions that cryptographically
 * bind the claim to the asset content.
 *
 * @param assertionLabel - The assertion label to check
 * @returns True if the assertion is a hard binding assertion
 */
export function isHardBindingAssertion(assertionLabel: string): boolean {
    return (
        assertionLabel === 'c2pa.hash.data' ||
        assertionLabel === 'c2pa.hash.bmff' ||
        assertionLabel === 'c2pa.hash.boxes'
    );
}

/**
 * Extract assertion label from JUMBF URI
 *
 * Parses a JUMBF URI to extract just the assertion label component.
 *
 * @param jumbfUri - JUMBF URI (e.g., "self#jumbf=c2pa/uuid/c2pa.assertions/c2pa.hash.data")
 * @returns Assertion label (e.g., "c2pa.hash.data") or null if unable to parse
 *
 * @example
 * extractAssertionLabel("self#jumbf=c2pa/uuid/c2pa.assertions/c2pa.hash.data")
 * // Returns: "c2pa.hash.data"
 */
export function extractAssertionLabel(jumbfUri: string): string | null {
    const match = /c2pa\.assertions\/([^/]+)$/.exec(jumbfUri);
    return match ? match[1] : null;
}

/**
 * Compute cryptographic hash of data
 *
 * @param data - The data to hash
 * @param algorithm - Hash algorithm name (sha256, sha384, or sha512)
 * @returns Promise resolving to the hash bytes
 * @throws Error if the algorithm is not supported
 */
export async function computeHash(data: Uint8Array, algorithm: string): Promise<Uint8Array> {
    const algorithmMap: Record<string, HashAlgorithm> = {
        sha256: 'SHA-256',
        sha384: 'SHA-384',
        sha512: 'SHA-512',
    };

    const webCryptoAlg = algorithmMap[algorithm.toLowerCase()];
    if (!webCryptoAlg) {
        throw new Error(`Unsupported hash algorithm: ${algorithm}`);
    }

    const hashBuffer = await Crypto.digest(data, webCryptoAlg);
    return new Uint8Array(hashBuffer);
}

/**
 * Compare two byte arrays for equality
 *
 * @param a - First byte array
 * @param b - Second byte array
 * @returns True if both arrays are equal
 */
export function arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    return a.every((byte, i) => byte === b[i]);
}

/**
 * Deep equality check using JSON serialization
 *
 * Note: This approach may not work correctly with all object types.
 *
 * @param a - First value to compare
 * @param b - Second value to compare
 * @returns True if both values are deeply equal
 */
export function deepEqual(a: unknown, b: unknown): boolean {
    return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Check if a Uint8Array is missing or empty
 *
 * @param data - The data to check
 * @returns True if data is null, undefined, or has length 0
 */
export function isEmptyOrMissing(data: Uint8Array | null | undefined): boolean {
    return !data || data.length === 0;
}

/**
 * Convert a private JWK to a public JWK
 *
 * Removes private key parameters from a JSON Web Key, leaving only the public key information.
 *
 * @param privateJwk - Private JWK containing private parameters
 * @returns Public JWK with only public parameters
 */
export function privateJwkToPublicJwk({ kty, crv, x, y, n, e }: JsonWebKey): JsonWebKey {
    return { ...{ kty, crv, x, y, n, e } };
}
