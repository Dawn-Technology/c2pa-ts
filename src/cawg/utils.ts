/**
 * CAWG Identity Assertion Utilities
 * Helper functions for CBOR serialization, hashing, and data transformation
 *
 * @module cawg/utils
 */
import * as cborX from 'cbor-x';
import { Crypto, HashAlgorithm } from '../crypto';
import { Claim, IdentityAssertion } from '../manifest/index.js';
import type { C2paAssetBinding, HashedUriMap, HashMap, SignerPayloadMap } from './types.js';

/**
 * Serialize signer_payload using CBOR deterministic encoding
 * as specified in RFC 8949, Section 4.2.1
 */
export function serializeSignerPayload(payload: SignerPayloadMap): Uint8Array {
    // Use deterministic encoding for consistent results
    return cborX.encode(payload);
}

/**
 * Deserialize CBOR-encoded signer_payload
 */
export function deserializeSignerPayload(data: Uint8Array): SignerPayloadMap {
    return cborX.decode(data) as SignerPayloadMap;
}

/**
 * Serialize claim data using CBOR deterministic encoding
 */
export function serializeClaimData(payload: Claim): Uint8Array {
    // Use deterministic encoding for consistent results
    return cborX.encode(payload);
}

/**
 * Deserialize CBOR-encoded claim data
 */
export function deserializeClaimData(data: Uint8Array): Claim {
    return cborX.decode(data) as Claim;
}

/**
 * Serialize complete identity assertion to CBOR
 */
export function serializeIdentityAssertion(assertion: IdentityAssertion): Uint8Array {
    return cborX.encode(assertion);
}

/**
 * Deserialize CBOR-encoded identity assertion
 */
export function deserializeIdentityAssertion(data: Uint8Array): IdentityAssertion {
    return cborX.decode(data) as IdentityAssertion;
}

/**
 * Validate that padding contains only zero (0x00) bytes
 */
export function validatePadding(pad: Uint8Array): boolean {
    return pad.every(byte => byte === 0x00);
}

/**
 * Create a padding buffer filled with zero bytes
 */
export function createPadding(size: number): Uint8Array {
    return new Uint8Array(size);
}

/**
 * Calculate required padding size to match target size
 * Takes into account CBOR encoding overhead
 */
export function calculatePaddingSize(currentSize: number, targetSize: number): { pad1: number; pad2: number } {
    const remaining = targetSize - currentSize;

    // Account for CBOR variable-length integer encoding
    // When length goes from 0-23 (1 byte), to 24-255 (2 bytes), to 256-65535 (3 bytes), etc.
    // the encoded size jumps

    // Start with pad2 = 0
    let pad2 = 0;
    let pad1 = remaining;

    // Check if we can't express this padding with a single field
    // (e.g., when we need exactly 25 bytes but encoding jumps from 24 to 26)
    const encodedSize1 = getCborByteStringEncodingSize(pad1);
    if (encodedSize1 !== remaining) {
        // Split between pad1 and pad2
        // Try to use most of the space in pad1
        pad1 = Math.max(0, remaining - 10);
        const encoded1 = getCborByteStringEncodingSize(pad1);
        pad2 = Math.max(0, remaining - encoded1);
    }

    return { pad1, pad2 };
}

/**
 * Get the total encoded size of a CBOR byte string
 * (including the length prefix)
 */
function getCborByteStringEncodingSize(dataLength: number): number {
    if (dataLength <= 23) {
        return 1 + dataLength; // 1-byte length prefix
    } else if (dataLength <= 0xff) {
        return 2 + dataLength; // 1-byte type + 1-byte length
    } else if (dataLength <= 0xffff) {
        return 3 + dataLength; // 1-byte type + 2-byte length
    } else if (dataLength <= 0xffffffff) {
        return 5 + dataLength; // 1-byte type + 4-byte length
    } else {
        return 9 + dataLength; // 1-byte type + 8-byte length
    }
}

/**
 * Convert CBOR byte strings to base64 for JSON representation
 */
export function bytesToBase64(bytes: Uint8Array): string {
    // Use standard base64 encoding (not URL-safe)
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Convert base64 string to byte array
 */
export function base64ToBytes(base64: string | Uint8Array): Uint8Array {
    // If input is already a number array, convert directly to Uint8Array
    let base64String: string;
    if (Array.isArray(base64)) {
        base64String = new TextDecoder().decode(new Uint8Array(base64));
    } else if (base64 instanceof Uint8Array) {
        base64String = new TextDecoder().decode(base64);
    } else {
        base64String = base64;
    }
    return Uint8Array.from(Buffer.from(base64String, 'base64'));
}

/**
 * Convert signer_payload to C2PA asset binding format for verifiable credentials
 * Converts CBOR byte strings to base64
 */
export function signerPayloadToC2paAssetBinding(payload: SignerPayloadMap): C2paAssetBinding {
    return {
        referenced_assertions: payload.referenced_assertions.map(ra => ({
            url: ra.url,
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
 * Converts base64 strings to CBOR byte arrays
 */
export function c2paAssetBindingToSignerPayload(binding: C2paAssetBinding): SignerPayloadMap {
    return {
        referenced_assertions: binding.referenced_assertions.map(ra => ({
            url: ra.url,
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
 */
export function hashMapsEqual(a: HashMap, b: HashMap): boolean {
    if (a.alg !== b.alg) return false;
    if (a.hash.length !== b.hash.length) return false;
    return a.hash.every((byte, i) => byte === b.hash[i]);
}

/**
 * Check if two hashed URI maps are equal
 */
export function hashedUriMapsEqual(a: HashedUriMap, b: HashedUriMap): boolean {
    if (a.url !== b.url) return false;
    if (a.alg !== b.alg) return false;
    if (a.hash.length !== b.hash.length) return false;
    return a.hash.every((byte, i) => byte === b.hash[i]);
}

/**
 * Find duplicates in an array of hashed URI maps
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
 * Validate label format according to CAWG specification
 * Labels are organized into namespaces using period as separator
 */
export function validateLabel(label: string): boolean {
    if (!label || label.length === 0) return false;

    // ABNF: namespaced-label = qualified-namespace label
    // qualified-namespace = "cawg" / entity
    // entity = entity-component *( "." entity-component )
    // entity-component = 1( DIGIT / ALPHA ) *( DIGIT / ALPHA / "-" / "_" )
    // label = 1*( "." label-component )
    // label-component = 1( DIGIT / ALPHA ) *( DIGIT / ALPHA / "-" / "_" )

    const parts = label.split('.');
    if (parts.length < 2) return false;

    const componentRegex = /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/;
    return parts.every(part => componentRegex.test(part));
}

/**
 * Check if a label is in the CAWG namespace
 */
export function isCawgLabel(label: string): boolean {
    return label.startsWith('cawg.');
}

/**
 * Generate a unique label for multiple identity assertions
 * Uses double underscore (__) as separator per CAWG spec
 */
export function generateUniqueLabel(baseLabel: string, index: number): string {
    if (index === 0) return baseLabel;
    return `${baseLabel}__${index}`;
}

/**
 * Replace hash values with zero bytes for partial claim computation
 */
export function replaceHashWithZeros(hash: Uint8Array): Uint8Array {
    return new Uint8Array(hash.length);
}

/**
 * Check if an assertion is a hard binding assertion
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
 * Example: "self#jumbf=c2pa/uuid/c2pa.assertions/c2pa.hash.data" -> "c2pa.hash.data"
 */
export function extractAssertionLabel(jumbfUri: string): string | null {
    const match = /c2pa\.assertions\/([^/]+)$/.exec(jumbfUri);
    return match ? match[1] : null;
}

/**
 * Helper: Compute cryptographic hash
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
 * Helper: Compare two byte arrays
 */
export function arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    return a.every((byte, i) => byte === b[i]);
}

/**
 * Helper: Deep equality check
 */
export function deepEqual(a: unknown, b: unknown): boolean {
    return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Helper: Check if Uint8Array does not exist or is empty
 */
export function isEmptyOrMissing(data: Uint8Array | null | undefined): boolean {
    return !data || data.length === 0;
}
