import * as JUMBF from '../jumbf';
import { IdentityAssertion, Manifest, ValidationResult } from '../manifest';
import { IdentityAssertionValidator } from './identity-assertion-validator';
import { IdentityClaimsAggregationValidator } from './identity-claims-aggregation-validator';
import { CawgValidationOptions } from './types';

export class CawgValidator {
    manifest: Manifest;
    assertion: IdentityAssertion;
    assertionLabel: string;
    sourceBox: JUMBF.SuperBox;
    options: CawgValidationOptions;

    result: ValidationResult;

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

    async validate(): Promise<ValidationResult> {
        this.result.merge(await this.validateIdentityAssertion());
        this.result.merge(await this.validateIdentityClaimsAggregation());

        return this.result;
    }

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
