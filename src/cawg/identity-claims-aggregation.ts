/**
 * CAWG Identity Claims Aggregation Support
 * Implementation of ICA verifiable credentials per CAWG spec Section 8.1
 *
 * @module cawg/identity-claims-aggregation
 */
import { Signer } from '../cose';
import { SigStructure } from '../cose/SigStructure';
import { CBORBox } from '../jumbf';
import { IdentitySigner } from './identity-signer';
import {
    SCHEMA_URL,
    VC_CONTEXT,
    VC_TYPE,
    VerifiedIdentity,
    type CredentialStatus,
    type SignerPayloadMap,
    type VerifiableCredential,
} from './types.js';
import { signerPayloadToC2paAssetBinding } from './utils.js';

export class IdentityClaimsAggregation {
    /** The signer instance used to sign credentials */
    signer: IdentitySigner | Signer;

    /**
     * Creates a new IdentityClaimsAggregation instance
     *
     * @param signer - The signer (either IdentitySigner or generic Signer)
     */
    constructor(signer: IdentitySigner | Signer) {
        this.signer = signer;
    }

    /**
     * Create an Identity Claims Aggregation credential
     *
     * Creates an unsigned ICA verifiable credential that binds verified identities
     * to a C2PA asset via the signer_payload. The credential can be signed separately
     * using createIcaSignature().
     *
     * @param issuer - DID of the identity claims aggregator
     * @param verifiedIdentities - Array of verified identities (or single identity)
     * @param signerPayload - The signer_payload to bind to C2PA asset
     * @param validFrom - Valid from date (RFC 3339 format)
     * @param options - Additional credential options
     * @param options.validUntil - Credential expiration date
     * @param options.useVc2 - Use W3C VC Data Model 2.0 (default: true)
     * @param options.credentialStatus - Optional credential status information
     * @returns Unsigned ICA verifiable credential
     */
    static createIcaCredential(
        issuer: string,
        verifiedIdentities: VerifiedIdentity | VerifiedIdentity[],
        signerPayload: SignerPayloadMap,
        validFrom: Date,
        options?: {
            validUntil?: Date;
            useVc2?: boolean;
            credentialStatus?: CredentialStatus;
        },
    ): VerifiableCredential {
        const useVc2 = options?.useVc2 ?? true;

        // Convert signer_payload to C2PA asset binding format
        const c2paAssetBinding = signerPayloadToC2paAssetBinding(signerPayload);

        const credential: VerifiableCredential = {
            '@context': [useVc2 ? VC_CONTEXT.V2_0 : VC_CONTEXT.V1_1, VC_CONTEXT.CAWG],
            type: [VC_TYPE.Verifiable, VC_TYPE.IdentityClaimsAggregation],
            issuer,
            credentialSubject: {
                verifiedIdentities: Array.isArray(verifiedIdentities) ? verifiedIdentities : [verifiedIdentities],
                c2paAsset: c2paAssetBinding,
            },
            credentialSchema: [
                {
                    id: useVc2 ? SCHEMA_URL.VC2_0 : SCHEMA_URL.VC1_1,
                    type: 'JSONSchema',
                },
            ],
        };

        // Add validity dates based on VC version
        if (useVc2) {
            credential.validFrom = validFrom.toISOString();
            if (options?.validUntil) {
                credential.validUntil = options.validUntil.toISOString();
            }
        } else {
            credential.issuanceDate = validFrom.toISOString();
            if (options?.validUntil) {
                credential.expirationDate = options.validUntil.toISOString();
            }
        }

        // Add optional credential status
        if (options?.credentialStatus) {
            credential.credentialStatus = options.credentialStatus;
        }

        return credential;
    }

    /**
     * Create a signed ICA credential
     *
     * Signs the ICA credential using the configured signer's algorithm
     * and returns the COSE_Sign1 structure as bytes.
     *
     * @param icaCredential - The unsigned ICA credential to sign
     * @returns Promise resolving to the signed credential bytes
     */
    async createIcaSignature(icaCredential: VerifiableCredential): Promise<Uint8Array> {
        const icaCredentialBytes = new TextEncoder().encode(JSON.stringify(icaCredential));
        const icaSignature = await this.createIcaCoseSign1(icaCredentialBytes);
        return icaSignature;
    }

    /**
     * Create a COSE_Sign1 structure for the ICA credential
     *
     * Encodes the credential payload using COSE_Sign1 format as specified
     * in RFC 8152, with the signer's algorithm in the protected header.
     *
     * @param payload - The serialized credential bytes
     * @returns Promise resolving to the encoded COSE_Sign1 structure
     */
    async createIcaCoseSign1(payload: Uint8Array): Promise<Uint8Array> {
        const protectedHeaderBytes = CBORBox.encoder.encode({
            '1': this.signer.algorithm,
            '3': 'application/vc',
        });

        const toBeSigned = new SigStructure('Signature1', protectedHeaderBytes, payload).encode();
        const signature = await this.signer.sign(toBeSigned);

        const coseSign1 = [protectedHeaderBytes, {}, payload, signature];
        const cborBox = new CBORBox();
        cborBox.tag = 18;
        cborBox.content = coseSign1;
        cborBox.generateRawContent();
        return cborBox.rawContent!;
    }
}
