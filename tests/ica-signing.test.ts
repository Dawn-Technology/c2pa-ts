import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { afterAll, describe, it } from 'bun:test';
import { JPEG } from '../src/asset';
import { createIcaCredential, didResolver, SignatureType } from '../src/cawg';
import { CoseAlgorithmIdentifier, Signer } from '../src/cose';
import { SigStructure } from '../src/cose/SigStructure';
import { CBORBox, SuperBox } from '../src/jumbf';
import {
    Assertion,
    DataHashAssertion,
    IdentityAssertion,
    Manifest,
    ManifestStore,
    ValidationStatusCode,
} from '../src/manifest';
import { loadTestCertificate, TEST_CERTIFICATES } from './utils/testCertificates';

async function getSignerPublicJwk(signer: Signer): Promise<JsonWebKey> {
    const spki = new Uint8Array(signer.certificate.publicKey.rawData);
    let importAlgorithm: EcKeyImportParams | Algorithm;
    if (signer.algorithm === CoseAlgorithmIdentifier.Ed25519) {
        importAlgorithm = { name: 'Ed25519' };
    } else {
        importAlgorithm = {
            name: 'ECDSA',
            namedCurve: 'P-256',
        };
    }

    const publicKey = await crypto.subtle.importKey('spki', spki, importAlgorithm, true, ['verify']);
    return crypto.subtle.exportKey('jwk', publicKey);
}

function createDidJwk(publicJwk: JsonWebKey): string {
    // did:jwk requires a base64url-encoded JSON JWK as method-specific identifier.
    const canonicalJwk = Object.fromEntries(Object.entries(publicJwk).sort(([a], [b]) => a.localeCompare(b)));
    const didPayload = Buffer.from(JSON.stringify(canonicalJwk), 'utf8').toString('base64url');
    return `did:jwk:${didPayload}`;
}

function installDidResolverMock(issuerDid: string, publicJwk: JsonWebKey): () => void {
    const originalResolve = didResolver.resolve.bind(didResolver);
    didResolver.resolve = (async (did: string) => {
        if (did !== issuerDid) {
            return originalResolve(did);
        }

        const methodId = `${issuerDid}#key-1`;
        return {
            didDocument: {
                id: issuerDid,
                verificationMethod: [
                    {
                        id: methodId,
                        type: 'JsonWebKey2020',
                        controller: issuerDid,
                        publicKeyJwk: publicJwk,
                    },
                ],
                assertionMethod: [methodId],
            },
            didResolutionMetadata: {},
            didDocumentMetadata: {},
        };
    }) as typeof didResolver.resolve;

    return () => {
        didResolver.resolve = originalResolve;
    };
}

async function createIcaCoseSign1(payload: Uint8Array, signer: Signer): Promise<Uint8Array> {
    const protectedHeaderBytes = CBORBox.encoder.encode({
        '1': signer.algorithm,
        '3': 'application/vc',
    });

    const toBeSigned = new SigStructure('Signature1', protectedHeaderBytes, payload).encode();
    const signature = await signer.sign(toBeSigned);

    const coseSign1 = [protectedHeaderBytes, {}, payload, signature];
    const cborBox = new CBORBox();
    cborBox.tag = 18;
    cborBox.content = coseSign1;
    cborBox.generateRawContent();
    return cborBox.rawContent!;
}

function adjustIdentityAssertionSize(
    identityAssertion: IdentityAssertion,
    manifest: Manifest,
    targetAssertionSize: number,
): void {
    for (let i = 0; i < 4; i++) {
        const currentSize = identityAssertion.generateJUMBFBox(manifest.claim).toBuffer(false).length;
        if (currentSize === targetAssertionSize) {
            return;
        }
        if (currentSize > targetAssertionSize) {
            throw new Error('ICA credential exceeds reserved assertion size');
        }

        const delta = targetAssertionSize - currentSize;
        identityAssertion.pad1 = new Uint8Array(identityAssertion.pad1.length + delta).fill(0x00);
    }

    const finalSize = identityAssertion.generateJUMBFBox(manifest.claim).toBuffer(false).length;
    if (finalSize !== targetAssertionSize) {
        throw new Error('Failed to match reserved identity assertion size');
    }
}

// Location of the image to sign with identity assertion
const sourceFile = 'tests/fixtures/dawn-technology-icon.jpg';
const targetFile = 'tests/fixtures/dawn-technology-icon-signed-with-ica.jpg';

describe('ICA (identity claims aggregation) Signing Tests', function () {
    for (const certificate of TEST_CERTIFICATES) {
        describe(`using ${certificate.name}`, function () {
            let manifest: Manifest | undefined;
            let issuerDid: string | undefined;
            let issuerPublicJwk: JsonWebKey | undefined;

            it('add a manifest with ICA (identity claims aggregation) to a JPEG test file', async function () {
                const { signer, timestampProvider } = await loadTestCertificate(certificate);

                // Load the file into a buffer
                const buf = await fs.readFile(sourceFile);
                assert.ok(buf);

                // Ensure it's a JPEG
                assert.ok(await JPEG.canRead(buf));

                // Construct the asset
                const asset = await JPEG.create(buf);

                // Create a new manifest store and append a new manifest
                const manifestStore = new ManifestStore();
                manifest = manifestStore.createManifest({
                    assetFormat: 'image/jpeg',
                    instanceID: 'ica-test-xyz',
                    defaultHashAlgorithm: 'SHA-256',
                    signer,
                });

                // Create a data hash assertion (hard binding)
                const dataHashAssertion = DataHashAssertion.create('SHA-256');
                manifest.addAssertion(dataHashAssertion);

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
                    SignatureType.IdentityClaimsAggregation,
                    ['cawg.creator'],
                );
                // Reserve enough space up-front for the real COSE_Sign1 ICA credential.
                identityAssertion.setSignature(new Uint8Array(4096).fill(0xaa), new Uint8Array(256).fill(0x00));

                // Add the ICA (identity claims aggregation) assertion to the manifest
                manifest.addAssertion(identityAssertion);

                const reservedIdentityAssertionSize = identityAssertion
                    .generateJUMBFBox(manifest.claim)
                    .toBuffer(false).length;

                // Make space in the asset for the manifest (now includes ICA assertion)
                await asset.ensureManifestSpace(manifestStore.measureSize());

                // Update the hard binding with the asset
                await dataHashAssertion.updateWithAsset(asset);

                // Data hash assertion should have a hash after updateWithAsset
                assert(dataHashAssertion.hash, 'Data hash assertion should have a hash after updateWithAsset');

                // First signing pass populates claim assertion hashes used by hard-binding validation.
                await manifest.sign(signer, timestampProvider);

                assert(manifest.claim, 'Manifest claim missing after signing');

                const hardBindingRef = manifest.claim.assertions.find(
                    ref => ref.uri === `self#jumbf=c2pa.assertions/${dataHashAssertion.fullLabel}`,
                );
                assert(hardBindingRef, 'Hard binding reference not found in claim assertions');

                // Update the ICA (identity claims aggregation) assertion with the correct hash
                identityAssertion.setSignerPayload(
                    [
                        {
                            url: hardBindingRef.uri,
                            hash: hardBindingRef.hash,
                        },
                    ],
                    SignatureType.IdentityClaimsAggregation,
                    ['cawg.creator'],
                );

                issuerPublicJwk = await getSignerPublicJwk(signer);
                issuerDid = createDidJwk(issuerPublicJwk);
                const icaCredential = createIcaCredential(
                    issuerDid,
                    {
                        verifiedIdentities: [
                            {
                                type: 'cawg.social_media',
                                name: 'Sample Creator',
                                username: 'sample-creator',
                                uri: 'https://example.com/sample-creator',
                                provider: {
                                    id: 'https://example.com',
                                    name: 'Example Identity Provider',
                                },
                                verifiedAt: new Date().toISOString(),
                            },
                        ],
                    },
                    identityAssertion.signerPayload,
                    new Date(),
                );

                const icaCredentialBytes = new TextEncoder().encode(JSON.stringify(icaCredential));
                const icaSignature = await createIcaCoseSign1(icaCredentialBytes, signer);

                identityAssertion.setSignature(icaSignature, new Uint8Array(256).fill(0x00));
                adjustIdentityAssertionSize(identityAssertion, manifest, reservedIdentityAssertionSize);

                // Create the manifest signature
                await manifest.sign(signer, timestampProvider);

                // Write the JUMBF box to the asset
                await asset.writeManifestJUMBF(manifestStore.getBytes());

                // Write the asset to the target file
                await fs.writeFile(targetFile, await asset.getDataRange());
            });

            it('decode verifiedIdentities from the ICA credential in the signed JPEG', async function () {
                if (!manifest) return;

                const buf = await fs.readFile(targetFile).catch(() => undefined);
                if (!buf) return;

                const asset = await JPEG.create(buf);
                const jumbf = await asset.getManifestJUMBF();
                assert.ok(jumbf, 'no JUMBF found');

                const superBox = SuperBox.fromBuffer(jumbf);
                const manifestStore = ManifestStore.read(superBox);
                const activeManifest = manifestStore.getActiveManifest();
                assert.ok(activeManifest, 'no active manifest found');

                const identityAssertion = activeManifest.assertions?.assertions.find(
                    (a: Assertion) => a.label === 'cawg.identity',
                );
                assert.ok(identityAssertion instanceof IdentityAssertion, 'no IdentityAssertion found');

                // Decode the COSE_Sign1 structure embedded in the assertion signature
                const coseDecoded = CBORBox.decoder.decode(identityAssertion.signature) as {
                    value: [Uint8Array, unknown, Uint8Array, Uint8Array];
                };
                assert.ok(Array.isArray(coseDecoded.value) && coseDecoded.value.length === 4, 'invalid COSE_Sign1');

                // Payload is the JSON-encoded ICA credential
                const [, , payloadBytes] = coseDecoded.value;
                const credential = JSON.parse(new TextDecoder().decode(payloadBytes)) as {
                    credentialSubject: {
                        verifiedIdentities: {
                            type: string;
                            name?: string;
                            username?: string;
                            uri?: string;
                            provider?: { id: string; name: string };
                            verifiedAt: string;
                        }[];
                    };
                };

                const verifiedIdentities = credential.credentialSubject.verifiedIdentities;

                assert.ok(
                    Array.isArray(verifiedIdentities) && verifiedIdentities.length > 0,
                    'verifiedIdentities is empty',
                );
                assert.equal(verifiedIdentities[0].type, 'cawg.social_media');
                assert.equal(verifiedIdentities[0].name, 'Sample Creator');
                assert.equal(verifiedIdentities[0].username, 'sample-creator');
                assert.equal(verifiedIdentities[0].uri, 'https://example.com/sample-creator');
                assert.equal(verifiedIdentities[0].provider?.name, 'Example Identity Provider');
            });

            it('read and verify the JPEG with ICA (identity claims aggregation) assertion', async function () {
                if (!manifest) return;

                // Load the file into a buffer
                const buf = await fs.readFile(targetFile).catch(() => undefined);
                if (!buf) return;

                // Ensure it's a JPEG
                assert.ok(await JPEG.canRead(buf));

                // Construct the asset
                const asset = await JPEG.create(buf);

                // Extract the C2PA manifest store in binary JUMBF format
                const jumbf = await asset.getManifestJUMBF();
                assert.ok(jumbf, 'no JUMBF found');

                // Deserialize the JUMBF box structure
                const superBox = SuperBox.fromBuffer(jumbf);

                // Construct the manifest store from the JUMBF box
                const manifestStore = ManifestStore.read(superBox);

                // Get the active manifest
                const activeManifest = manifestStore.getActiveManifest();
                assert.ok(activeManifest, 'no active manifest found');

                // Find the ICA (identity claims aggregation) assertion
                const identityAssertion = activeManifest.assertions?.assertions.find(
                    (a: Assertion) => a.label === 'cawg.identity',
                );
                assert.ok(identityAssertion, 'ICA (identity claims aggregation) assertion not found');
                assert.ok(identityAssertion instanceof IdentityAssertion, 'assertion is not an IdentityAssertion');

                // Verify ICA (identity claims aggregation) assertion properties
                assert.equal(identityAssertion.signerPayload.sig_type, SignatureType.IdentityClaimsAggregation);
                assert.deepEqual(identityAssertion.signerPayload.role, ['cawg.creator']);
                assert.equal(identityAssertion.signerPayload.referenced_assertions.length, 1);

                // Verify the manifest signature
                if (!issuerDid || !issuerPublicJwk) {
                    throw new Error('Missing mocked DID issuer data for validation');
                }
                const restoreDidResolver = installDidResolverMock(issuerDid, issuerPublicJwk);
                const validationResult = await manifestStore.validate(asset);
                restoreDidResolver();

                // Check overall validity
                assert.ok(validationResult.isValid, 'Validation result invalid');

                // Verify ICA (identity claims aggregation) assertion is present in the validation
                const identityHashCheck = validationResult.statusEntries.find(
                    e => e.code === ValidationStatusCode.AssertionHashedURIMatch && e.url?.includes('cawg.identity'),
                );
                assert.ok(identityHashCheck?.success, 'ICA (identity claims aggregation) assertion hash check failed');
            });
        });
    }

    afterAll(async function () {
        // Delete test file, ignore the case it doesn't exist
        await fs.unlink(targetFile).catch(() => undefined);
    });
});
