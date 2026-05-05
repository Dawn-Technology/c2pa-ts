/**
 * CAWG Identity Assertion Validation
 * Functions for validating identity assertions according to CAWG specification v1.2
 *
 * @module cawg/validator
 */

import * as JUMBF from '../jumbf';
import { Assertion, Claim, Manifest, ValidationResult, ValidationStatusCode } from '../manifest';
import { IdentityAssertion } from '../manifest/assertions/IdentityAssertion';
import {
    SignatureType,
    type ExpectedCountersignerMap,
    type HashedUriMap,
    type HashMap,
    type CawgValidationOptions,
    type SignerPayloadMap,
} from './types.js';
import {
    arrayEquals,
    computeHash,
    deepEqual,
    extractAssertionLabel,
    findDuplicateReferences,
    hashMapsEqual,
    isEmptyOrMissing,
    isHardBindingAssertion,
    serializeClaimData,
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
    options: CawgValidationOptions = {},
): Promise<ValidationResult> {
    const result: ValidationResult = new ValidationResult();

    // Step 1: Verify hard binding assertion is included and correct
    result.merge(
        await validateHardBindingReference(assertion.signerPayload.referenced_assertions, manifest, sourceBox),
    );

    // Step 2: Validate required fields
    if (!assertion.signerPayload || isEmptyOrMissing(assertion.signature) || isEmptyOrMissing(assertion.pad1)) {
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

    if (!payload.sig_type || !Object.values(SignatureType).includes(payload.sig_type as SignatureType)) {
        result.addError(
            ValidationStatusCode.IdentitySigTypeUnknown,
            sourceBox,
            'signer_payload missing or unknown sig_type',
        );
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

    // Step 7: Validate expected_partial_claim if present
    if (payload.expected_partial_claim) {
        result.merge(await validateExpectedPartialClaim(payload, sourceBox, assertionLabel));
    }

    // Step 8: Validate expected_claim_generator if present
    if (payload.expected_claim_generator) {
        result.merge(await validateExpectedClaimGenerator(payload.expected_claim_generator, sourceBox));
    }

    // Step 9: Validate expected_countersigners if present
    if (payload.expected_countersigners) {
        result.merge(await validateExpectedCountersigners(payload.expected_countersigners, sourceBox, assertionLabel));
    }

    // Step 10: Validate signature based on sig_type
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
        const found = manifest.assertions?.getAssertionsByLabel(extractAssertionLabel(ref.url) ?? '');

        if (!found || found.length === 0) {
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
    const expectedHardBindings = manifest.claim?.assertions?.filter(
        assertion => assertion.uri && isHardBindingAssertion(extractAssertionLabel(assertion.uri) ?? ''),
    );

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
        const expectedHardBinding = expectedHardBindings.find(binding => binding.uri === ref.url);
        return (
            expectedHardBinding &&
            hashMapsEqual(
                { hash: ref.hash, alg: '' },
                {
                    hash: expectedHardBinding.hash,
                    alg: '',
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
        const modifiedClaim = JSON.parse(JSON.stringify(sourceBox)) as Claim;

        // Replace current identity assertion hash with zeros
        replaceAssertionHash(modifiedClaim, assertionLabel);

        // Replace expected countersigners' hashes with zeros
        if (payload.expected_countersigners) {
            // Implementation depends on matching credentials
            // Simplified for now
        }

        // Serialize and hash
        const serialized = serializeClaimData(modifiedClaim);
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
    expectedCountersigners: ExpectedCountersignerMap[],
    sourceBox: JUMBF.SuperBox,
    assertionLabel: string,
): Promise<ValidationResult> {
    const result = new ValidationResult();

    // TODO Find all other identity assertions in the manifest
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
            // TODO
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
function replaceAssertionHash(claimData: Claim, label: string): void {
    const assertions = claimData.assertions ?? [];

    for (const assertion of assertions) {
        const assertionLabel = extractAssertionLabel(assertion.uri);
        if (assertionLabel === label) {
            assertion.hash = new Uint8Array(assertion.hash.length);
        }
    }
}

/**
 * Helper: Extract claim generator certificate
 */
function extractClaimGeneratorCertificate(claimData: JUMBF.SuperBox): Uint8Array | null {
    // TODO Extract from claim signature structure
    return null;
}

/**
 * Helper: Find other identity assertions in claim
 */
function findIdentityAssertions(claimData: JUMBF.SuperBox, excludeLabel: string): IdentityAssertion[] {
    // TODO  Implementation would find all identity assertions
    // except the one with excludeLabel
    return [];
}

/**
 * Helper: Validate countersigner credentials
 */
async function validateCountersignerCredentials(assertion: Assertion, expectedCredentials: HashMap): Promise<boolean> {
    // TODO Extract and hash credentials from assertion
    // Implementation depends on credential type
    return true; // Simplified
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
