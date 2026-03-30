/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { afterAll, describe, it } from 'bun:test';
import { JPEG } from '../src/asset';
import { Crypto } from '../src/crypto';
import { SuperBox } from '../src/jumbf';
import {
    Assertion,
    DataHashAssertion,
    IdentityAssertion,
    Manifest,
    ManifestStore,
    ValidationStatusCode,
} from '../src/manifest';
import { loadTestCertificate, TEST_CERTIFICATES } from './utils/testCertificates';

// Location of the image to sign with identity assertion
const sourceFile = 'tests/fixtures/trustnxt-icon.jpg';
const targetFile = 'tests/fixtures/trustnxt-icon-signed-with-identity.jpg';

describe('Identity Assertion Signing Tests', function () {
    for (const certificate of TEST_CERTIFICATES) {
        describe(`using ${certificate.name}`, function () {
            let manifest: Manifest | undefined;

            it('add a manifest with identity assertion to a JPEG test file', async function () {
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
                    instanceID: 'identity-test-xyz',
                    defaultHashAlgorithm: 'SHA-256',
                    signer,
                });

                // Create a data hash assertion (hard binding)
                const dataHashAssertion = DataHashAssertion.create('SHA-256');
                manifest.addAssertion(dataHashAssertion);

                // Create an identity assertion with placeholder values
                const identityAssertion = new IdentityAssertion();
                // Set preliminary values with placeholder hash
                identityAssertion.setSignerPayload(
                    [
                        {
                            url: `self#jumbf=c2pa.assertions/c2pa.hash.data`,
                            alg: 'SHA-256',
                            hash: new Uint8Array(32).fill(0), //new Uint8Array([ 86, 223, 145, 128, 77, 182, 43, 147, 97, 1, 171, 0, 65, 143, 91, 140, 253, 192, 120, 131, 101, 185, 56, 87, 70, 245, 27, 148, 6, 135, 224, 248 ])
                        },
                    ],
                    'cawg.x509.cose',
                    ['cawg.creator'],
                );
                identityAssertion.setSignature(new Uint8Array(64).fill(0xaa), new Uint8Array(256).fill(0x00));

                // Add the identity assertion to the manifest
                manifest.addAssertion(identityAssertion);

                // Make space in the asset for the manifest (now includes identity assertion)
                await asset.ensureManifestSpace(manifestStore.measureSize());

                // Update the hard binding with the asset
                await dataHashAssertion.updateWithAsset(asset);

                // Data hash assertion should have a hash after updateWithAsset
                assert(dataHashAssertion.hash, 'Data hash assertion should have a hash after updateWithAsset');

                // Update the identity assertion with the correct hash
                identityAssertion.setSignerPayload(
                    [
                        {
                            url: `self#jumbf=c2pa.assertions/c2pa.hash.data`,
                            alg: 'SHA-256',
                            hash: dataHashAssertion.hash,
                        },
                    ],
                    'cawg.x509.cose',
                    ['cawg.creator'],
                );

                // Set signature and padding (in real implementation, this would be a proper COSE signature)
                // For testing purposes, we'll use placeholder values
                // identityAssertion.setSignature(new Uint8Array(64).fill(0xab), new Uint8Array(256).fill(0x01));

                // Create the manifest signature
                await manifest.sign(signer, timestampProvider);

                // Write the JUMBF box to the asset
                await asset.writeManifestJUMBF(manifestStore.getBytes());

                // Write the asset to the target file
                await fs.writeFile(targetFile, await asset.getDataRange());
            });

            it('read and verify the JPEG with identity assertion', async function () {
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

                // Find the identity assertion
                const identityAssertion = activeManifest.assertions?.assertions.find(
                    (a: Assertion) => a.label === 'cawg.identity',
                );
                assert.ok(identityAssertion, 'identity assertion not found');
                assert.ok(identityAssertion instanceof IdentityAssertion, 'assertion is not an IdentityAssertion');

                // Verify identity assertion properties
                assert.equal(identityAssertion.signerPayload.sig_type, 'cawg.x509.cose');
                assert.deepEqual(identityAssertion.signerPayload.role, ['cawg.creator']);
                assert.equal(identityAssertion.signerPayload.referenced_assertions.length, 1);

                // Verify the manifest signature
                const validationResult = await manifestStore.validate(asset);

                // Check overall validity
                assert.ok(validationResult.isValid, 'Validation result invalid');

                // Verify identity assertion is present in the validation
                const identityHashCheck = validationResult.statusEntries.find(
                    e => e.code === ValidationStatusCode.AssertionHashedURIMatch && e.url?.includes('cawg.identity'),
                );
                assert.ok(identityHashCheck?.success, 'Identity assertion hash check failed');
            });
        });
    }

    afterAll(async function () {
        // Delete test file, ignore the case it doesn't exist
        await fs.unlink(targetFile).catch(() => undefined);
    });
});

describe('Identity Assertion with Multiple Roles', function () {
    let manifest: Manifest | undefined;
    const targetFileMultiRole = 'tests/fixtures/trustnxt-icon-signed-multi-role.jpg';

    it('create manifest with identity assertion having multiple roles', async function () {
        const { signer, timestampProvider } = await loadTestCertificate(TEST_CERTIFICATES[0]);

        const buf = await fs.readFile(sourceFile);
        const asset = await JPEG.create(buf);

        const manifestStore = new ManifestStore();
        manifest = manifestStore.createManifest({
            assetFormat: 'image/jpeg',
            instanceID: 'multi-role-test',
            defaultHashAlgorithm: 'SHA-256',
            signer,
        });

        const dataHashAssertion = DataHashAssertion.create('SHA-256');
        manifest.addAssertion(dataHashAssertion);

        const identityAssertion = new IdentityAssertion();
        // Set preliminary values with placeholder hash
        identityAssertion.setSignerPayload(
            [
                {
                    url: `self#jumbf=/c2pa/${manifest.label}/c2pa.assertions/${dataHashAssertion.fullLabel}`,
                    alg: 'sha256',
                    hash: new Uint8Array(32).fill(0), // Placeholder
                },
            ],
            'cawg.x509.cose',
            ['cawg.creator', 'cawg.editor', 'cawg.contributor'],
        );
        identityAssertion.setSignature(new Uint8Array(64).fill(0xbb), new Uint8Array(256).fill(0x00));
        manifest.addAssertion(identityAssertion);

        await asset.ensureManifestSpace(manifestStore.measureSize());
        await dataHashAssertion.updateWithAsset(asset);

        const dataHashAssertionBox = dataHashAssertion.generateJUMBFBox(manifest.claim);
        const dataHashAssertionBytes = dataHashAssertionBox.toBuffer(false);
        const dataHashAssertionHash = await Crypto.digest(dataHashAssertionBytes, 'SHA-256');

        // Update with correct hash
        identityAssertion.setSignerPayload(
            [
                {
                    url: `self#jumbf=/c2pa/${manifest.label}/c2pa.assertions/${dataHashAssertion.fullLabel}`,
                    alg: 'sha256',
                    hash: dataHashAssertionHash,
                },
            ],
            'cawg.x509.cose',
            ['cawg.creator', 'cawg.editor', 'cawg.contributor'],
        );

        identityAssertion.setSignature(new Uint8Array(64).fill(0xbb), new Uint8Array(256).fill(0x00));

        await manifest.sign(signer, timestampProvider);
        await asset.writeManifestJUMBF(manifestStore.getBytes());
        await fs.writeFile(targetFileMultiRole, await asset.getDataRange());
    });

    it('verify identity assertion with multiple roles', async function () {
        if (!manifest) return;

        const buf = await fs.readFile(targetFileMultiRole);
        const asset = await JPEG.create(buf);
        const jumbf = await asset.getManifestJUMBF();
        assert.ok(jumbf);

        const superBox = SuperBox.fromBuffer(jumbf);
        const manifestStore = ManifestStore.read(superBox);
        const activeManifest = manifestStore.getActiveManifest();
        assert.ok(activeManifest);

        const identityAssertion = activeManifest.assertions?.assertions.find(
            (a: Assertion) => a.label === 'cawg.identity',
        );
        assert.ok(identityAssertion instanceof IdentityAssertion);

        // Verify multiple roles
        assert.deepEqual(identityAssertion.signerPayload.role, ['cawg.creator', 'cawg.editor', 'cawg.contributor']);
    });

    afterAll(async function () {
        await fs.unlink(targetFileMultiRole).catch(() => undefined);
    });
});

describe('Identity Assertion with Optional Fields', function () {
    let manifest: Manifest | undefined;
    const targetFileOptional = 'tests/fixtures/trustnxt-icon-signed-optional-fields.jpg';

    it('create manifest with identity assertion with optional fields', async function () {
        const { signer, timestampProvider } = await loadTestCertificate(TEST_CERTIFICATES[0]);

        const buf = await fs.readFile(sourceFile);
        const asset = await JPEG.create(buf);

        const manifestStore = new ManifestStore();
        manifest = manifestStore.createManifest({
            assetFormat: 'image/jpeg',
            instanceID: 'optional-fields-test',
            defaultHashAlgorithm: 'SHA-256',
            signer,
        });

        const dataHashAssertion = DataHashAssertion.create('SHA-256');
        manifest.addAssertion(dataHashAssertion);

        const identityAssertion = new IdentityAssertion();
        // Set preliminary values with placeholder hashes
        identityAssertion.setSignerPayload(
            [
                {
                    url: `self#jumbf=/c2pa/${manifest.label}/c2pa.assertions/${dataHashAssertion.fullLabel}`,
                    alg: 'sha256',
                    hash: new Uint8Array(32).fill(0), // Placeholder
                },
            ],
            'cawg.x509.cose',
            ['cawg.publisher'],
            {
                expectedPartialClaim: { alg: 'sha256', hash: new Uint8Array(32).fill(0x11) },
                expectedClaimGenerator: { alg: 'sha256', hash: new Uint8Array(32).fill(0x22) },
            },
        );
        const placeholderPad2 = new Uint8Array(128).fill(0x00);
        identityAssertion.setSignature(new Uint8Array(64).fill(0xcc), new Uint8Array(256).fill(0x00), placeholderPad2);
        manifest.addAssertion(identityAssertion);

        await asset.ensureManifestSpace(manifestStore.measureSize());
        await dataHashAssertion.updateWithAsset(asset);

        const dataHashAssertionBox = dataHashAssertion.generateJUMBFBox(manifest.claim);
        const dataHashAssertionBytes = dataHashAssertionBox.toBuffer(false);
        const dataHashAssertionHash = await Crypto.digest(dataHashAssertionBytes, 'SHA-256');

        // Update with correct hash and options
        const expectedPartialClaim = {
            alg: 'sha256',
            hash: new Uint8Array(32).fill(0x11),
        };

        const expectedClaimGenerator = {
            alg: 'sha256',
            hash: new Uint8Array(32).fill(0x22),
        };

        identityAssertion.setSignerPayload(
            [
                {
                    url: `self#jumbf=/c2pa/${manifest.label}/c2pa.assertions/${dataHashAssertion.fullLabel}`,
                    alg: 'sha256',
                    hash: dataHashAssertionHash,
                },
            ],
            'cawg.x509.cose',
            ['cawg.publisher'],
            {
                expectedPartialClaim,
                expectedClaimGenerator,
            },
        );

        identityAssertion.setSignature(new Uint8Array(64).fill(0xcc), new Uint8Array(256).fill(0x00), placeholderPad2);

        await manifest.sign(signer, timestampProvider);
        await asset.writeManifestJUMBF(manifestStore.getBytes());
        await fs.writeFile(targetFileOptional, await asset.getDataRange());
    });

    it('verify identity assertion with optional fields', async function () {
        if (!manifest) return;

        const buf = await fs.readFile(targetFileOptional);
        const asset = await JPEG.create(buf);
        const jumbf = await asset.getManifestJUMBF();
        assert.ok(jumbf);

        const superBox = SuperBox.fromBuffer(jumbf);
        const manifestStore = ManifestStore.read(superBox);
        const activeManifest = manifestStore.getActiveManifest();
        assert.ok(activeManifest);

        const identityAssertion = activeManifest.assertions?.assertions.find(
            (a: Assertion) => a.label === 'cawg.identity',
        );
        assert.ok(identityAssertion instanceof IdentityAssertion);

        // Verify optional fields are present
        assert.ok(identityAssertion.signerPayload.expected_partial_claim);
        assert.equal(identityAssertion.signerPayload.expected_partial_claim.alg, 'sha256');

        assert.ok(identityAssertion.signerPayload.expected_claim_generator);
        assert.equal(identityAssertion.signerPayload.expected_claim_generator.alg, 'sha256');

        // Verify pad2 is present
        assert.ok(identityAssertion.pad2);
        assert.equal(identityAssertion.pad2.length, 128);
    });

    afterAll(async function () {
        await fs.unlink(targetFileOptional).catch(() => undefined);
    });
});

describe('Identity Assertion Reference Verification', function () {
    it('should correctly hash and reference data hash assertion', async function () {
        const { signer } = await loadTestCertificate(TEST_CERTIFICATES[0]);

        const buf = await fs.readFile(sourceFile);
        const asset = await JPEG.create(buf);

        const manifestStore = new ManifestStore();
        const manifest = manifestStore.createManifest({
            assetFormat: 'image/jpeg',
            instanceID: 'reference-test',
            defaultHashAlgorithm: 'SHA-256',
            signer,
        });

        const dataHashAssertion = DataHashAssertion.create('SHA-256');
        manifest.addAssertion(dataHashAssertion);

        await asset.ensureManifestSpace(manifestStore.measureSize());
        await dataHashAssertion.updateWithAsset(asset);

        // Calculate the hash of the data hash assertion
        const dataHashAssertionBox = dataHashAssertion.generateJUMBFBox(manifest.claim);
        const dataHashAssertionBytes = dataHashAssertionBox.toBuffer(false);
        const dataHashAssertionHash = await Crypto.digest(dataHashAssertionBytes, 'SHA-256');

        // Verify the hash is valid
        assert.ok(dataHashAssertionHash instanceof Uint8Array);
        assert.equal(dataHashAssertionHash.length, 32);

        // Create identity assertion with the reference
        const identityAssertion = new IdentityAssertion();
        identityAssertion.setSignerPayload(
            [
                {
                    url: `self#jumbf=/c2pa/${manifest.label}/c2pa.assertions/${dataHashAssertion.fullLabel}`,
                    alg: 'sha256',
                    hash: dataHashAssertionHash,
                },
            ],
            'cawg.x509.cose',
            ['cawg.creator'],
        );

        // Verify the referenced assertion URL is correctly formatted
        assert.ok(identityAssertion.signerPayload.referenced_assertions[0].url.startsWith('self#jumbf=/c2pa/'));
        assert.ok(identityAssertion.signerPayload.referenced_assertions[0].url.includes('c2pa.assertions'));
        assert.ok(identityAssertion.signerPayload.referenced_assertions[0].url.includes('c2pa.hash.data'));
    });
});
