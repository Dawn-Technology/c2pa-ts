import { calculatePaddingSize, createPadding, serializeIdentityAssertion, validateIdentityAssertion } from '../../cawg';
import * as JUMBF from '../../jumbf';
import { BinaryHelper } from '../../util';
import { Claim } from '../Claim';
import { Manifest } from '../Manifest';
import * as raw from '../rawTypes';
import { ValidationStatusCode } from '../types';
import { ValidationError } from '../ValidationError';
import { ValidationResult } from '../ValidationResult';
import { Assertion } from './Assertion';

/**
 * Hash algorithm and value map used in CAWG identity assertions
 */
interface HashMap {
    alg: string;
    hash: Uint8Array;
}

/**
 * Hashed URI map structure referencing C2PA assertions
 */
interface HashedUriMap {
    url: string;
    alg?: string;
    hash: Uint8Array;
}

/**
 * Expected countersigner information
 */
interface ExpectedCountersignerMap {
    partial_signer_payload: SignerPayloadMap;
    expected_credentials?: HashMap;
}

/**
 * Signer payload map - the core data structure signed by the credential holder
 */
interface SignerPayloadMap {
    referenced_assertions: HashedUriMap[];
    sig_type: string;
    role?: string[];
    expected_partial_claim?: HashMap;
    expected_claim_generator?: HashMap;
    expected_countersigners?: ExpectedCountersignerMap[];
}

/**
 * Raw identity assertion structure as stored in CBOR
 */
interface RawIdentityAssertion {
    signer_payload: SignerPayloadMap;
    signature: Uint8Array;
    // signature_info?: any;
    pad1: Uint8Array;
    pad2?: Uint8Array;
}

/**
 * CAWG Identity Assertion
 *
 * Implementation of the Creator Assertions Working Group (CAWG) identity assertion.
 * This assertion binds a credential holder's identity to specific C2PA assertions
 * and provides cryptographic proof of that binding through digital signatures.
 *
 * @see https://creator-assertions.github.io/identity/1.2/
 */
export class IdentityAssertion extends Assertion {
    public label = 'cawg.identity' as const;
    public uuid = raw.UUIDs.cborAssertion;

    /** Content to be signed by credential holder */
    public signerPayload: SignerPayloadMap = {
        referenced_assertions: [],
        sig_type: '',
    };

    /** Raw byte stream of the credential holder's signature */
    public signature: Uint8Array = new Uint8Array();

    /** Padding field filled with 0x00 values */
    public pad1: Uint8Array = new Uint8Array();

    /** Optional second padding field filled with 0x00 values */
    public pad2?: Uint8Array;

    public readContentFromJUMBF(box: JUMBF.IBox, claim: Claim): void {
        if (!(box instanceof JUMBF.CBORBox) || !this.uuid || !BinaryHelper.bufEqual(this.uuid, raw.UUIDs.cborAssertion))
            throw new ValidationError(
                ValidationStatusCode.AssertionCBORInvalid,
                this.sourceBox,
                'Identity assertion has invalid type',
            );

        const rawContent = box.content as RawIdentityAssertion;

        if (!rawContent.signer_payload)
            throw new ValidationError(
                ValidationStatusCode.AssertionCBORInvalid,
                this.sourceBox,
                'Identity assertion is missing signer_payload',
            );

        if (!rawContent.signature)
            throw new ValidationError(
                ValidationStatusCode.AssertionCBORInvalid,
                this.sourceBox,
                'Identity assertion is missing signature',
            );

        if (!rawContent.pad1)
            throw new ValidationError(
                ValidationStatusCode.AssertionCBORInvalid,
                this.sourceBox,
                'Identity assertion is missing pad1',
            );

        this.signerPayload = {
            referenced_assertions: rawContent.signer_payload.referenced_assertions.map(refAssertion => ({
                url: refAssertion.url,
                alg: refAssertion.alg,
                hash: refAssertion.hash,
            })),
            sig_type: rawContent.signer_payload.sig_type,
            role: rawContent.signer_payload.role,
            expected_partial_claim: rawContent.signer_payload.expected_partial_claim,
            expected_claim_generator: rawContent.signer_payload.expected_claim_generator,
            expected_countersigners: rawContent.signer_payload.expected_countersigners,
        };

        this.signature = rawContent.signature;
        this.pad1 = rawContent.pad1;
        this.pad2 = rawContent.pad2;
    }

    public generateJUMBFBoxForContent(claim?: Claim): JUMBF.IBox {
        const box = new JUMBF.CBORBox();

        const rawContent: RawIdentityAssertion = {
            signer_payload: this.signerPayload,
            signature: this.signature,
            // signature_info: {
            //     "alg": "Es256",
            // },
            pad1: this.pad1,
        };

        if (this.pad2) {
            rawContent.pad2 = this.pad2;
        }

        box.content = rawContent;
        return box;
    }

    public override async validate(manifest: Manifest): Promise<ValidationResult> {
        const result = await super.validate(manifest);

        if (!this.sourceBox) {
            throw new ValidationError(
                ValidationStatusCode.AssertionCBORInvalid,
                undefined,
                'Identity assertion is missing source box reference',
            );
        }
        result.merge(await validateIdentityAssertion(manifest, this, this.label, this.sourceBox));
        return result;
    }

    /**
     * Sets the signer payload with referenced assertions and signature type
     */
    public setSignerPayload(
        referencedAssertions: HashedUriMap[],
        sigType: string,
        roles?: string[],
        options?: {
            expectedPartialClaim?: HashMap;
            expectedClaimGenerator?: HashMap;
            expectedCountersigners?: ExpectedCountersignerMap[];
        },
    ): void {
        this.signerPayload = {
            referenced_assertions: referencedAssertions,
            sig_type: sigType,
            role: roles,
            expected_partial_claim: options?.expectedPartialClaim,
            expected_claim_generator: options?.expectedClaimGenerator,
            expected_countersigners: options?.expectedCountersigners,
        };
    }

    /**
     * Sets the signature and padding fields
     */
    public setSignature(signature: Uint8Array, pad1: Uint8Array, pad2?: Uint8Array): void {
        this.signature = signature;

        this.pad1 = pad1;
        this.pad2 = pad2;
    }

    /**
     * Create the final identity assertion after obtaining signature
     *
     * @param signerPayload - The signer_payload structure (must match what was signed)
     * @param signature - The credential holder's signature over signer_payload
     * @param placeholderSize - Optional size of placeholder assertion (if used)
     * @returns Complete identity assertion structure
     */
    static createIdentityAssertion(
        signerPayload: SignerPayloadMap,
        signature: Uint8Array,
        placeholderSize?: number,
    ): IdentityAssertion {
        // Create initial assertion without padding
        const assertion = new IdentityAssertion();
        assertion.signerPayload = signerPayload;
        assertion.signature = signature;
        assertion.pad1 = new Uint8Array(0);
        assertion.pad2 = new Uint8Array(0);
        // If placeholder size is specified, calculate padding
        if (placeholderSize !== undefined) {
            const currentSize = serializeIdentityAssertion(assertion).length;

            if (currentSize > placeholderSize) {
                throw new Error(
                    `Signature size (${currentSize} bytes) exceeds placeholder size (${placeholderSize} bytes). ` +
                        'Repeat claim generation with a larger placeholder.',
                );
            }

            // Calculate padding to match placeholder size
            const padding = calculatePaddingSize(currentSize, placeholderSize);
            assertion.pad1 = createPadding(padding.pad1);

            if (padding.pad2 > 0) {
                assertion.pad2 = createPadding(padding.pad2);
            }
        }

        return assertion;
    }
}
