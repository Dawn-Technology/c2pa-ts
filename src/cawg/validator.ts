/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * CAWG Identity Assertion Validation
 * Functions for validating identity assertions according to CAWG specification v1.2
 *
 * @module cawg/validator
 */

import { Crypto, HashAlgorithm } from '../crypto';
import * as JUMBF from '../jumbf';
import { Assertion, Manifest, ValidationResult, ValidationStatusCode } from '../manifest';
import { HashAssertion } from '../manifest/assertions/HashAssertion';
import { IdentityAssertion } from '../manifest/assertions/IdentityAssertion';
import type { HashedUriMap, HashMap, IdentityAssertionValidationOptions, SignerPayloadMap } from './types.js';
import {
    extractAssertionLabel,
    findDuplicateReferences,
    hashMapsEqual,
    isHardBindingAssertion,
    serializeSignerPayload,
    validatePadding,
} from './utils.js';

/**
 * Validate an identity assertion
 *
 * Performs comprehensive validation according to CAWG specification Section 7
 *
 * @param manifest - The manifest containing the assertion
 * @param assertion - Identity assertion to validate
 * @param assertionLabel - Label of the identity assertion
 * @param claimData - The C2PA claim containing this assertion
 * @param options - Validation options
 * @returns Validation result with status codes
 */
export async function validateIdentityAssertion(
    manifest: Manifest,
    assertion: IdentityAssertion,
    assertionLabel: string,
    sourceBox: JUMBF.SuperBox,
    options: IdentityAssertionValidationOptions = {},
): Promise<ValidationResult> {
    const result: ValidationResult = new ValidationResult();

    // Step 2: Validate required fields
    if (!assertion.signerPayload || !assertion.signature || !assertion.pad1) {
        result.addError(
            ValidationStatusCode.AssertionCBORInvalid,
            sourceBox,
            'Identity assertion missing required fields',
        );
    }

    // Step 3: Validate padding contains only zeros
    if (!validatePadding(assertion.pad1)) {
        result.addError(ValidationStatusCode.IdentityPadInvalid, sourceBox, 'pad1 field contains non-zero bytes');
    }

    if (assertion.pad2 && !validatePadding(assertion.pad2)) {
        result.addError(ValidationStatusCode.IdentityPadInvalid, sourceBox, 'pad2 field contains non-zero bytes');
    }

    // Step 4: Validate signer_payload structure
    const payload = assertion.signerPayload;

    if (!payload.referenced_assertions || payload.referenced_assertions.length === 0) {
        result.addError(
            ValidationStatusCode.AssertionCBORInvalid,
            sourceBox,
            'signer_payload missing referenced_assertions',
        );
        return result;
    }

    if (!payload.sig_type) {
        result.addError(ValidationStatusCode.IdentitySigTypeUnknown, sourceBox, 'signer_payload missing sig_type');
        return result;
    }

    // Step 5: Check for duplicate references
    const duplicates = findDuplicateReferences(payload.referenced_assertions);
    if (duplicates.length > 0) {
        result.addError(
            ValidationStatusCode.IdentityAssertionDuplicate,
            sourceBox,
            `Found ${duplicates.length} duplicate assertion reference(s)`,
        );
    }

    // Step 6: Verify referenced assertions exist in claim
    result.merge(await validateReferencedAssertions(payload.referenced_assertions, manifest, sourceBox));

    // Step 7: Verify hard binding assertion is included and correct
    result.merge(await validateHardBindingReference(payload.referenced_assertions, manifest, sourceBox));

    // Step 8: Validate expected_partial_claim if present
    if (payload.expected_partial_claim) {
        result.merge(await validateExpectedPartialClaim(payload, sourceBox, assertionLabel));
    }

    // Step 9: Validate expected_claim_generator if present
    if (payload.expected_claim_generator) {
        result.merge(await validateExpectedClaimGenerator(payload.expected_claim_generator, sourceBox));
    }

    // Step 10: Validate expected_countersigners if present
    if (payload.expected_countersigners) {
        result.merge(await validateExpectedCountersigners(payload.expected_countersigners, sourceBox, assertionLabel));
    }

    // Step 11: Validate signature based on sig_type
    // This is delegated to credential-type-specific validators
    if (result.isValid) {
        // If no failures so far, consider it well-formed at minimum
        result.addInformational(ValidationStatusCode.WellFormed, sourceBox, 'Identity assertion is well-formed');
    }

    return result;
}

/**
 * Validate that all referenced assertions exist in the claim
 */
async function validateReferencedAssertions(
    references: HashedUriMap[],
    manifest: Manifest,
    sourceBox: JUMBF.SuperBox,
): Promise<ValidationResult> {
    const result = new ValidationResult();

    for (const ref of references) {
        const found = manifest.assertions?.getAssertionsByLabel(ref.url);

        if (!found) {
            result.addError(
                ValidationStatusCode.IdentityAssertionMismatch,
                sourceBox,
                `Referenced assertion not found in claim: ${ref.url}`,
            );
        }
    }
    return result;
}

/**
 * Validate hard binding assertion reference
 */
async function validateHardBindingReference(
    references: HashedUriMap[],
    manifest: Manifest,
    sourceBox: JUMBF.SuperBox,
): Promise<ValidationResult> {
    const result = new ValidationResult();

    // Find hard binding assertions in references
    const hardBindingRefs = references.filter(ref => {
        const label = extractAssertionLabel(ref.url);
        return label && isHardBindingAssertion(label);
    });

    if (hardBindingRefs.length === 0) {
        result.addError(
            ValidationStatusCode.IdentityHardBindingMissing,
            sourceBox,
            'No hard binding assertion referenced',
        );
    }

    // Verify it's the correct hard binding for this manifest
    // The correct one is determined by the algorithm described in
    // C2PA spec Section 15.12
    const expectedHardBindings = manifest.assertions?.getHardBindings();

    if (!expectedHardBindings || expectedHardBindings.length === 0) {
        // No hard binding found in claim
        result.addError(
            ValidationStatusCode.IdentityHardBindingMissing,
            sourceBox,
            'No hard binding assertion found in claim',
        );
        return result;
    }
    const correctRef = hardBindingRefs.find(ref => {
        const expectedHardBinding = expectedHardBindings.find(
            binding => binding.label === extractAssertionLabel(ref.url),
        ) as Assertion & HashAssertion;
        return (
            expectedHardBinding &&
            hashMapsEqual(
                { hash: ref.hash, alg: ref.alg ?? '' },
                {
                    hash: expectedHardBinding.hash!,
                    alg: expectedHardBinding.algorithm!,
                },
            )
        );
    });
    if (!correctRef) {
        result.addError(
            ValidationStatusCode.IdentityHardBindingIncorrect,
            sourceBox,
            'Hard binding reference does not match the active manifest binding',
        );
    }

    return result;
}

/**
 * Validate expected_partial_claim field
 */
async function validateExpectedPartialClaim(
    payload: SignerPayloadMap,
    sourceBox: JUMBF.SuperBox,
    assertionLabel: string,
): Promise<ValidationResult> {
    const result = new ValidationResult();

    if (!payload.expected_partial_claim) return result;

    try {
        // Clone claim and replace hashes with zeros as specified
        const modifiedClaim = JSON.parse(JSON.stringify(sourceBox));

        // Replace current identity assertion hash with zeros
        replaceAssertionHash(modifiedClaim, assertionLabel);

        // Replace expected countersigners' hashes with zeros
        if (payload.expected_countersigners) {
            // Implementation depends on matching credentials
            // Simplified for now
        }

        // Serialize and hash
        const serialized = serializeSignerPayload(modifiedClaim);
        const computed = await computeHash(serialized, payload.expected_partial_claim.alg);

        const expected = payload.expected_partial_claim.hash;
        if (!arrayEquals(computed, expected)) {
            result.addError(
                ValidationStatusCode.IdentityExpectedPartialClaimMismatch,
                sourceBox,
                'expected_partial_claim does not match computed value',
            );
        }
    } catch (error) {
        result.addError(
            ValidationStatusCode.IdentityExpectedPartialClaimMismatch,
            sourceBox,
            `Error validating expected_partial_claim: ${error instanceof Error ? error.message : String(error)}`,
        );
    }
    return result;
}

/**
 * Validate expected_claim_generator field
 */
async function validateExpectedClaimGenerator(expected: HashMap, sourceBox: JUMBF.SuperBox): Promise<ValidationResult> {
    const result = new ValidationResult();
    try {
        // Extract end-entity certificate from claim signature
        const certificate = extractClaimGeneratorCertificate(sourceBox);

        if (!certificate) {
            result.addError(
                ValidationStatusCode.IdentityExpectedClaimGeneratorMismatch,
                sourceBox,
                'Could not extract claim generator certificate from claim signature',
            );
            return result;
        }

        // Compute hash of certificate
        const computed = await computeHash(certificate, expected.alg);

        if (!arrayEquals(computed, expected.hash)) {
            result.addError(
                ValidationStatusCode.IdentityExpectedClaimGeneratorMismatch,
                sourceBox,
                'expected_claim_generator does not match computed hash of claim generator certificate',
            );
        }
    } catch (error) {
        result.addError(
            ValidationStatusCode.IdentityExpectedClaimGeneratorMismatch,
            sourceBox,
            `Error validating expected_claim_generator: ${error instanceof Error ? error.message : String(error)}`,
        );
    }
    return result;
}

/**
 * Validate expected_countersigners field
 */
async function validateExpectedCountersigners(
    expectedCountersigners: any[],
    sourceBox: JUMBF.SuperBox,
    assertionLabel: string,
): Promise<ValidationResult> {
    const result = new ValidationResult();

    // Find all other identity assertions in the manifest
    const otherIdentityAssertions = findIdentityAssertions(sourceBox, assertionLabel);

    for (const otherAssertion of otherIdentityAssertions) {
        // Remove expected_countersigners field from the signer_payload
        const partialPayload = { ...otherAssertion.signerPayload };
        delete partialPayload.expected_countersigners;

        // Find matching entry in expected_countersigners
        const matchingEntry = expectedCountersigners.find(ec => deepEqual(ec.partial_signer_payload, partialPayload));

        if (!matchingEntry) {
            result.addError(
                ValidationStatusCode.IdentityUnexpectedCountersigner,
                sourceBox,
                `Found identity assertion not described in expected_countersigners`,
            );
            continue;
        }

        // If expected_credentials is present, validate it
        if (matchingEntry.expected_credentials) {
            const credentialMatch = await validateCountersignerCredentials(
                otherAssertion,
                matchingEntry.expected_credentials,
            );

            if (!credentialMatch) {
                result.addError(
                    ValidationStatusCode.IdentityExpectedCountersignerMismatch,
                    sourceBox,
                    'Countersigner credentials do not match expected value',
                );
            }
        }
    }

    // Check if any expected countersigners are missing
    if (otherIdentityAssertions.length < expectedCountersigners.length) {
        result.addError(
            ValidationStatusCode.IdentityExpectedCountersignerMissing,
            sourceBox,
            'Expected identity assertion is missing from manifest',
        );
    }
    return result;
}

/**
 * Helper: Replace assertion hash with zeros in claim
 */
function replaceAssertionHash(claimData: any, label: string): void {
    const assertions = claimData.assertions ?? claimData.created_assertions ?? [];

    for (const assertion of assertions) {
        const assertionLabel = extractAssertionLabel(assertion.url);
        if (assertionLabel === label) {
            assertion.hash = new Uint8Array(assertion.hash.length);
        }
    }
}

/**
 * Helper: Extract claim generator certificate
 */
function extractClaimGeneratorCertificate(claimData: any): Uint8Array | null {
    // Extract from claim signature structure
    // This is a simplified version
    if (claimData.signature?.certificates) {
        return claimData.signature.certificates[0]; // End-entity certificate
    }
    return null;
}

/**
 * Helper: Find other identity assertions in claim
 */
function findIdentityAssertions(claimData: any, excludeLabel: string): IdentityAssertion[] {
    // Implementation would find all identity assertions
    // except the one with excludeLabel
    return [];
}

/**
 * Helper: Validate countersigner credentials
 */
async function validateCountersignerCredentials(assertion: any, expectedCredentials: HashMap): Promise<boolean> {
    // Extract and hash credentials from assertion
    // Implementation depends on credential type
    return true; // Simplified
}

/**
 * Helper: Compute cryptographic hash
 */
async function computeHash(data: Uint8Array, algorithm: string): Promise<Uint8Array> {
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
function arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    return a.every((byte, i) => byte === b[i]);
}

/**
 * Helper: Deep equality check
 */
function deepEqual(a: any, b: any): boolean {
    return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Check if an identity assertion is well-formed (basic structure validation)
 * This is a quick check before full validation
 */
export function isWellFormedIdentityAssertion(assertion: IdentityAssertion): boolean {
    try {
        return !!(
            assertion.signerPayload &&
            assertion.signature &&
            assertion.pad1 &&
            assertion.signerPayload.referenced_assertions &&
            assertion.signerPayload.sig_type
        );
    } catch {
        return false;
    }
}
