import 'core-js/full/reflect';
import { Asset } from '../../asset';
import {
    CawgTrustConfiguration,
    CawgValidator,
    ExpectedCountersignerMap,
    HashedUriMap,
    HashMap,
    IdentityClaimsAggregation,
    IdentitySigner,
    isEmptyOrMissing,
    NamedActorRole,
    RawIdentityAssertion,
    SignatureType,
    SignerPayloadMap,
} from '../../cawg';
import { Signer } from '../../cose';
import * as JUMBF from '../../jumbf';
import { LocalTimestampProvider } from '../../rfc3161';
import { BinaryHelper } from '../../util';
import { Claim } from '../Claim';
import { Manifest } from '../Manifest';
import * as raw from '../rawTypes';
import { ValidationStatusCode } from '../types';
import { ValidationError } from '../ValidationError';
import { ValidationResult } from '../ValidationResult';
import { Assertion } from './Assertion';
import { AssertionLabels } from './AssertionLabels';
import { DataHashAssertion } from './DataHashAssertion';

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
    public label = AssertionLabels.identity;
    public uuid = raw.UUIDs.cborAssertion;

    /** Content to be signed by credential holder */
    public signerPayload: SignerPayloadMap = {
        referenced_assertions: [],
        sig_type: SignatureType.IdentityClaimsAggregation,
    };

    /** Raw byte stream of the credential holder's signature */
    public signature: Uint8Array = new Uint8Array();

    /** Padding field filled with 0x00 values */
    public pad1: Uint8Array = new Uint8Array();

    /** Optional second padding field filled with 0x00 values */
    public pad2?: Uint8Array;

    public reservedSize: number | undefined;

    public readContentFromJUMBF(box: JUMBF.IBox): void {
        if (!(box instanceof JUMBF.CBORBox) || !this.uuid || !BinaryHelper.bufEqual(this.uuid, raw.UUIDs.cborAssertion))
            throw new ValidationError(
                ValidationStatusCode.AssertionCBORInvalid,
                this.sourceBox,
                'Identity assertion has invalid type',
            );

        const rawContent = box.content as RawIdentityAssertion;

        if (!rawContent.signer_payload)
            throw new ValidationError(
                ValidationStatusCode.IdentityCborInvalid,
                this.sourceBox,
                'Identity assertion is missing signer_payload',
            );

        if (isEmptyOrMissing(rawContent.signature))
            throw new ValidationError(
                ValidationStatusCode.IdentityCborInvalid,
                this.sourceBox,
                'Identity assertion is missing signature',
            );

        if (isEmptyOrMissing(rawContent.pad1))
            throw new ValidationError(
                ValidationStatusCode.IdentityCborInvalid,
                this.sourceBox,
                'Identity assertion is missing pad1',
            );

        this.signerPayload = {
            ...rawContent.signer_payload,
            referenced_assertions: rawContent.signer_payload.referenced_assertions.map(refAssertion => ({
                url: refAssertion.url,
                alg: refAssertion.alg,
                hash: refAssertion.hash,
            })),
            sig_type: rawContent.signer_payload.sig_type,
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
            pad1: this.pad1,
        };

        if (this.pad2) {
            rawContent.pad2 = this.pad2;
        }

        box.content = rawContent;
        return box;
    }

    public override async validate(
        manifest: Manifest,
        validationOptions?: CawgTrustConfiguration,
    ): Promise<ValidationResult> {
        const result = await super.validate(manifest);

        if (!this.sourceBox) {
            throw new ValidationError(
                ValidationStatusCode.AssertionCBORInvalid,
                undefined,
                'Identity assertion is missing source box reference',
            );
        }
        const cawgValidator = new CawgValidator(manifest, this, this.label, this.sourceBox, validationOptions);
        result.merge(await cawgValidator.validate());

        return result;
    }

    /**
     * Sets the signer payload with referenced assertions and signature type
     */
    public setSignerPayload(
        referencedAssertions: HashedUriMap[],
        sigType: SignatureType,
        roles?: NamedActorRole[],
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
    public setSignature(signature: Uint8Array, pad1: Uint8Array, pad2?: Uint8Array, manifest?: Manifest): void {
        this.signature = signature;

        this.pad1 = pad1;
        this.pad2 = pad2;

        if (!manifest) return;
        if (this.reservedSize) {
            this.adjustSize(manifest, this.reservedSize);
        } else {
            this.reservedSize = this.generateJUMBFBox(manifest.claim).toBuffer(false).length;
        }
    }

    public adjustSize(manifest: Manifest, targetAssertionSize: number): void {
        for (let i = 0; i < 4; i++) {
            const currentSize = this.generateJUMBFBox(manifest.claim).toBuffer(false).length;
            if (currentSize === targetAssertionSize) {
                return;
            }
            if (currentSize > targetAssertionSize) {
                throw new Error('ICA credential exceeds reserved assertion size');
            }

            const delta = targetAssertionSize - currentSize;
            this.pad1 = new Uint8Array(this.pad1.length + delta).fill(0x00);
        }

        const finalSize = this.generateJUMBFBox(manifest.claim).toBuffer(false).length;
        if (finalSize !== targetAssertionSize) {
            throw new Error('Failed to match reserved identity assertion size');
        }
    }

    /**
     * Create a manifest hard-binding assertion plus one CAWG identity assertion.
     *
     * Use this overload when a single identity signer should be attached.
     *
     * @param manifest - Manifest being populated and signed
     * @param asset - Asset the manifest is bound to
     * @param signer - Primary C2PA signer used for manifest signing
     * @param timestampProvider - RFC 3161 timestamp provider for manifest signatures
     * @param identitySigners - Single identity signer used to produce ICA credential
     * @returns Created hard-binding assertion and identity assertion
     */
    public static async create(
        manifest: Manifest,
        asset: Asset,
        signer: Signer,
        timestampProvider: LocalTimestampProvider,
        identitySigners: IdentitySigner,
    ): Promise<{ dataHashAssertion: DataHashAssertion; identityAssertion: IdentityAssertion }>;

    /**
     * Create a manifest hard-binding assertion plus multiple CAWG identity assertions.
     *
     * Use this overload when multiple identity signers should be attached.
     *
     * @param manifest - Manifest being populated and signed
     * @param asset - Asset the manifest is bound to
     * @param signer - Primary C2PA signer used for manifest signing
     * @param timestampProvider - RFC 3161 timestamp provider for manifest signatures
     * @param identitySigners - Identity signers used to produce ICA credentials
     * @returns Created hard-binding assertion and identity assertions
     */
    public static async create(
        manifest: Manifest,
        asset: Asset,
        signer: Signer,
        timestampProvider: LocalTimestampProvider,
        identitySigners: IdentitySigner[],
    ): Promise<{ dataHashAssertion: DataHashAssertion; identityAssertion: IdentityAssertion[] }>;

    /**
     * Create CAWG identity assertions and bind them to the active hard-binding assertion.
     *
     * Flow:
     * 1. Add hard-binding assertion placeholder.
     * 2. Add identity assertion placeholder(s) with reserved space.
     * 3. Sign manifest once to materialize claim assertion hashes.
     * 4. Replace placeholder hard-binding hash with actual hash.
     * 5. Build and sign ICA credential(s) and resize assertion padding.
     *
     * @param manifest - Manifest being populated and signed
     * @param asset - Asset the manifest is bound to
     * @param signer - Primary C2PA signer used for manifest signing
     * @param timestampProvider - RFC 3161 timestamp provider for manifest signatures
     * @param identitySigners - One or more identity signers
     * @returns Created hard-binding assertion and identity assertion(s)
     */
    public static async create(
        manifest: Manifest,
        asset: Asset,
        signer: Signer,
        timestampProvider: LocalTimestampProvider,
        identitySigners: IdentitySigner | IdentitySigner[],
    ): Promise<{ dataHashAssertion: DataHashAssertion; identityAssertion: IdentityAssertion | IdentityAssertion[] }> {
        // Create a data hash assertion (hard binding)
        const dataHashAssertion = DataHashAssertion.create('SHA-256');
        manifest.addAssertion(dataHashAssertion);

        // Normalize input so downstream logic can iterate uniformly.
        identitySigners = Array.isArray(identitySigners) ? identitySigners : [identitySigners];
        const identityAssertions: IdentityAssertion[] = [];
        for (const identitySigner of identitySigners) {
            // Create an ICA (identity claims aggregation) assertion with placeholder values
            const identityAssertion = new IdentityAssertion();
            // Set preliminary values with placeholder hash
            identityAssertion.setSignerPayload(
                [
                    {
                        url: `self#jumbf=c2pa.assertions/c2pa.hash.data`,
                        hash: new Uint8Array(32).fill(0x00),
                    },
                ],
                identitySigner.signatureType,
                identitySigner.roles,
            );
            // Reserve enough space up-front for the real COSE_Sign1 ICA credential.
            identityAssertion.setSignature(
                new Uint8Array(4096).fill(0xaa),
                new Uint8Array(256).fill(0x00),
                undefined,
                manifest,
            );

            manifest.addAssertion(identityAssertion);
            identityAssertions.push(identityAssertion);
        }

        // Make space in the asset for the manifest (now includes ICA assertion)
        await asset.ensureManifestSpace(manifest.parentStore.measureSize());

        // Update the hard binding with the asset
        await dataHashAssertion.updateWithAsset(asset);

        // First signing pass populates claim assertion hashes used by hard-binding validation.
        await manifest.sign(signer, timestampProvider);

        if (!manifest.claim) {
            throw new Error('Manifest claim is missing after signing');
        }
        const hardBindingRef = manifest.claim.assertions.find(
            ref => ref.uri === `self#jumbf=c2pa.assertions/${dataHashAssertion.fullLabel}`,
        );

        if (!hardBindingRef) {
            throw new Error('Hard binding reference is missing after signing');
        }

        // Replace placeholder content with real hard-binding references and ICA signatures.
        for (let i = 0; i < identityAssertions.length; i++) {
            const identityAssertion = identityAssertions[i];
            const identitySigner = identitySigners[i];

            // Update the ICA (identity claims aggregation) assertion with the correct hash
            identityAssertion.setSignerPayload(
                [
                    {
                        url: hardBindingRef.uri,
                        hash: hardBindingRef.hash,
                    },
                ],
                identitySigner.signatureType,
                identitySigner.roles,
            );

            const ica = new IdentityClaimsAggregation(identitySigner);
            // Build a verifiable credential bound to the finalized signer_payload.
            const icaCredential = IdentityClaimsAggregation.createIcaCredential(
                await identitySigner.issuerDid,
                identitySigner.verifiedIdentity,
                identityAssertion.signerPayload,
                new Date(),
            );

            // Produce COSE_Sign1 bytes and update padding to maintain reserved size.
            const icaSignature = await ica.createIcaSignature(icaCredential);
            identityAssertion.setSignature(icaSignature, new Uint8Array(256).fill(0x00), undefined, manifest);
        }

        // Return single or multiple identity assertions according to overload usage.
        return {
            dataHashAssertion,
            identityAssertion: Array.isArray(identityAssertions) ? identityAssertions : identityAssertions[0],
        };
    }
}
