import { Asset } from '../asset';
import { IdentityClaimsAggregation, IdentitySigner } from '../cawg';
import { Signer } from '../cose';
import { DataHashAssertion, IdentityAssertion, Manifest } from '../manifest';
import { LocalTimestampProvider } from '../rfc3161';
import { DataHashAssertionFactory } from './DataHashAssertionFactory';

export class IdentityAssertionFactory {
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
    public static async add(
        manifest: Manifest,
        asset: Asset,
        signer: Signer,
        identitySigners: IdentitySigner,
        timestampProvider?: LocalTimestampProvider,
    ): Promise<{ dataHashAssertion: DataHashAssertion; identityAssertion: IdentityAssertion }>;

    /**
     * Create a manifest hard-binding assertion plus multiple CAWG identity assertions.
     *
     * Use this overload when multiple identity signers should be attached.
     *
     * @param manifest - Manifest being populated and signed
     * @param asset - Asset the manifest is bound to
     * @param signer - Primary C2PA signer used for manifest signing
     * @param identitySigners - Identity signers used to produce ICA credentials
     * @param timestampProvider - RFC 3161 timestamp provider for manifest signatures
     * @returns Created hard-binding assertion and identity assertions
     */
    public static async add(
        manifest: Manifest,
        asset: Asset,
        signer: Signer,
        identitySigners: IdentitySigner[],
        timestampProvider?: LocalTimestampProvider,
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
     * @param identitySigners - One or more identity signers
     * @param timestampProvider - RFC 3161 timestamp provider for manifest signatures
     * @returns Created hard-binding assertion and identity assertion(s)
     */
    public static async add(
        manifest: Manifest,
        asset: Asset,
        signer: Signer,
        identitySigners: IdentitySigner | IdentitySigner[],
        timestampProvider?: LocalTimestampProvider,
    ): Promise<{ dataHashAssertion: DataHashAssertion; identityAssertion: IdentityAssertion | IdentityAssertion[] }> {
        // Get or create a data hash assertion (hard binding)
        const dataHashAssertion = DataHashAssertionFactory.ensure(manifest);

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
