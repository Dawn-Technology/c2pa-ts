/**
 * CAWG Validator
 * Main entry point for validating CAWG identity assertions
 *
 * Orchestrates validation of both identity assertions and identity claims aggregation
 * credentials according to CAWG specification v1.2
 *
 * @module cawg/validator
 */
import * as JUMBF from '../jumbf';
import { IdentityAssertion, Manifest, ValidationResult } from '../manifest';
import { IdentityAssertionValidator } from './identity-assertion-validator';
import { IdentityClaimsAggregationValidator } from './identity-claims-aggregation-validator';
import { CawgValidationOptions } from './types';

/**
 * Validates CAWG identity assertions and identity claims aggregation credentials
 *
 * This class serves as the main validator for CAWG assertions, coordinating validation
 * of the identity assertion structure and any associated ICA credentials.
 */
export class CawgValidator {
    /** The C2PA manifest being validated */
    manifest: Manifest;
    /** The identity assertion being validated */
    assertion: IdentityAssertion;
    /** The JUMBF label of the identity assertion */
    assertionLabel: string;
    /** The JUMBF SuperBox containing the assertion */
    sourceBox: JUMBF.SuperBox;
    /** Validation options and trust configuration */
    options: CawgValidationOptions;
    /** Accumulated validation result */
    result: ValidationResult;

    /**
     * Creates a new CAWG validator
     *
     * @param manifest - The C2PA manifest containing the assertion
     * @param assertion - The identity assertion to validate
     * @param assertionLabel - The JUMBF label path of the assertion
     * @param sourceBox - The JUMBF SuperBox containing the assertion
     * @param options - Validation options including trust configuration
     */
    constructor(
        manifest: Manifest,
        assertion: IdentityAssertion,
        assertionLabel: string,
        sourceBox: JUMBF.SuperBox,
        options: CawgValidationOptions = {},
    ) {
        this.manifest = manifest;
        this.assertion = assertion;
        this.assertionLabel = assertionLabel;
        this.sourceBox = sourceBox;
        this.options = options;

        this.result = new ValidationResult();
    }

    /**
     * Validate the identity assertion
     *
     * Performs comprehensive validation including both identity assertion structure
     * and identity claims aggregation credential validation
     *
     * @returns Promise resolving to the validation result
     */
    async validate(): Promise<ValidationResult> {
        this.result.merge(await this.validateIdentityAssertion());
        this.result.merge(await this.validateIdentityClaimsAggregation());

        return this.result;
    }

    /**
     * Validate the identity assertion structure
     *
     * Delegates to IdentityAssertionValidator to perform comprehensive validation
     * of the identity assertion according to CAWG specification Section 7
     *
     * @returns Promise resolving to identity assertion validation result
     */
    async validateIdentityAssertion(): Promise<ValidationResult> {
        const identityAssertionValidator = new IdentityAssertionValidator(
            this.manifest,
            this.assertion,
            this.assertionLabel,
            this.sourceBox,
            this.options,
        );
        return await identityAssertionValidator.validateIdentityAssertion();
    }

    /**
     * Validate the identity claims aggregation credential
     *
     * Delegates to IdentityClaimsAggregationValidator to perform comprehensive validation
     * of the ICA credential if present, according to CAWG specification Section 8.1
     *
     * @returns Promise resolving to ICA validation result
     */
    async validateIdentityClaimsAggregation(): Promise<ValidationResult> {
        const icaValidator = new IdentityClaimsAggregationValidator(
            this.assertion.signature,
            this.assertion.signerPayload,
            this.assertionLabel,
            this.options,
        );
        return await icaValidator.validateIcaCredential();
    }
}
