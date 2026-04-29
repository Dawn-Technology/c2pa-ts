/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { afterAll, describe, it } from 'bun:test';
import { JPEG } from '../src/asset';
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
const targetFile = 'tests/fixtures/trustnxt-icon-signed-with-ica.jpg';

describe('ICA (identity claims aggregation) Signing Tests', function () {
    for (const certificate of TEST_CERTIFICATES) {
        describe(`using ${certificate.name}`, function () {
            let manifest: Manifest | undefined;

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
                            alg: 'SHA-256',
                            hash: new Uint8Array(32).fill(0x00),
                        },
                    ],
                    'cawg.x509.cose',
                    ['cawg.creator'],
                );
                identityAssertion.setSignature(new Uint8Array(64).fill(0xaa), new Uint8Array(256).fill(0x00));

                // Add the ICA (identity claims aggregation) assertion to the manifest
                manifest.addAssertion(identityAssertion);

                // Make space in the asset for the manifest (now includes ICA assertion)
                await asset.ensureManifestSpace(manifestStore.measureSize());

                // Update the hard binding with the asset
                await dataHashAssertion.updateWithAsset(asset);

                // Data hash assertion should have a hash after updateWithAsset
                assert(dataHashAssertion.hash, 'Data hash assertion should have a hash after updateWithAsset');

                // Update the ICA (identity claims aggregation) assertion with the correct hash
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
                identityAssertion.setSignature(new Uint8Array(64).fill(0xaa), new Uint8Array(256).fill(0x00));

                // Create the manifest signature
                await manifest.sign(signer, timestampProvider);

                // Write the JUMBF box to the asset
                await asset.writeManifestJUMBF(manifestStore.getBytes());

                // Write the asset to the target file
                await fs.writeFile(targetFile, await asset.getDataRange());
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
                assert.equal(identityAssertion.signerPayload.sig_type, 'cawg.x509.cose');
                assert.deepEqual(identityAssertion.signerPayload.role, ['cawg.creator']);
                assert.equal(identityAssertion.signerPayload.referenced_assertions.length, 1);

                // Verify the manifest signature
                const validationResult = await manifestStore.validate(asset);

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
