import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { describe, it } from 'bun:test';
import { createAsset } from '../src/asset';
import { LocalSigner } from '../src/cose';
import { ManifestFactory, ValidationFactory } from '../src/factory';
import { SuperBox } from '../src/jumbf';
import { ManifestStore, ValidationStatusCode } from '../src/manifest';
import { loadTestCertificate, TEST_CERTIFICATES } from './utils/testCertificates';

const sourceFile = 'tests/fixtures/trustnxt-icon.jpg';

describe('Multi-manifest data hash regression', () => {
    it('prior manifest data hash should remain valid after a second manifest is added', async () => {
        const { signer, timestampProvider } = await loadTestCertificate(TEST_CERTIFICATES[0]);
        const localSigner = signer as LocalSigner;

        // Step 1: sign the original file to produce a file with manifest #1
        const buf = await fs.readFile(sourceFile);
        const file1 = new File([buf], 'trustnxt-icon.jpg', { type: 'image/jpeg' });
        const fileWithManifest1 = await ManifestFactory.buildAndFinish(file1, localSigner, timestampProvider);

        // Step 2: sign the result again to produce a file with both manifest #1 and manifest #2
        const fileWithManifest2 = await ManifestFactory.buildAndFinish(
            fileWithManifest1,
            localSigner,
            timestampProvider,
        );

        // Step 3: read back the manifest store from the final file
        const asset = await createAsset(fileWithManifest2);
        const jumbf = await asset.getManifestJUMBF();
        assert.ok(jumbf, 'Final file should contain a JUMBF manifest store');

        const manifestStore = ManifestStore.read(SuperBox.fromBuffer(jumbf));
        assert.equal(manifestStore.manifests.length, 2, 'Manifest store should contain exactly two manifests');

        // Step 4: validate all manifests against the asset
        const validationResults = await ValidationFactory.validateManifests(
            manifestStore as Parameters<typeof ValidationFactory.validateManifests>[0],
            asset,
            {},
        );
        assert.ok(validationResults, 'Validation results should be present');

        // Step 5: the prior manifest (manifest #1) should still have a valid data hash
        // This fails before the fix because the stored exclusion range only covers the
        // original (smaller) C2PA box; after manifest #2 is added the C2PA box grows
        // and bytes from manifest #2 bleed into the hash calculation.
        const [priorManifestLabel, priorManifestResult] = [...validationResults.entries()][0];
        assert.ok(priorManifestResult, `Validation result for prior manifest ${priorManifestLabel} should exist`);

        const dataHashEntry = priorManifestResult.statusEntries.find(
            e =>
                e.code === ValidationStatusCode.AssertionDataHashMatch ||
                e.code === ValidationStatusCode.AssertionDataHashMismatch,
        );
        assert.ok(dataHashEntry, 'Prior manifest should have a data hash status entry');
        assert.equal(
            dataHashEntry.code,
            ValidationStatusCode.AssertionDataHashMatch,
            `Prior manifest data hash should match, but got: ${dataHashEntry.code}`,
        );
    });
});
