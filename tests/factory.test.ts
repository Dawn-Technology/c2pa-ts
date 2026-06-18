import assert from 'node:assert/strict';
import { describe, it } from 'bun:test';
import { LocalIdentitySigner } from '../src/cawg';
import { LocalSigner } from '../src/cose';
import {
    ActionAssertionFactory,
    ExampleFactory,
    IdentityAssertionFactory,
    IngredientAssertionFactory,
    ManifestFactory,
    ThumbnailAssertionFactory,
    ValidationFactory,
} from '../src/factory';
import {
    ActionAssertion,
    Assertion,
    IdentityAssertion,
    IngredientAssertion,
    ThumbnailAssertion,
    ThumbnailType,
} from '../src/manifest';

describe('Factory tests', () => {
    it('Validating a file', async () => {
        // Get a file. Replace it with your own file
        const file: File = ExampleFactory.getTestFile();

        // Validate the file
        const { validationResult } = await ValidationFactory.validate(file);

        assert(!validationResult, 'No C2PA manifest');
    });

    it('Creating a manifest', async () => {
        // Get a file. Replace it with your own file
        const file: File = ExampleFactory.getTestFile();

        // Get a signer. Replace it with your own signer
        const signer: LocalSigner = ExampleFactory.getTestSigner();

        // Apply C2PA on a file and return the new file
        const fileWithManifest: File = await ManifestFactory.buildAndFinish(file, signer);

        assert(fileWithManifest instanceof File);

        const { validationResult } = await ValidationFactory.validate(fileWithManifest);
        assert(validationResult, 'Validation result should be present');
        assert(validationResult.size > 0, 'Validation result should contain at least one entry');
        for (const [label, result] of validationResult.entries()) {
            assert(label, 'Manifest label should be present');
            assert(result.isValid !== undefined);
            assert(result.statusEntries.length > 0, `Manifest with label ${label} should have statusEntries`);
            for (const statusEntry of result.statusEntries) {
                assert(statusEntry.code !== undefined, 'Status entry code should be defined');
                assert(statusEntry.success !== undefined, 'Status entry success should be defined');
            }
        }
    });

    it('Creating a manifest with an action, thumbnail and ingredient assertion', async () => {
        // Get a file. Replace it with your own file
        const file: File = ExampleFactory.getTestFile();

        // Get a thumbnail. Replace it with your own thumbnail
        const thumbnail: File = ExampleFactory.getTestFile();

        // Get a signer. Replace it with your own signer
        const signer: LocalSigner = ExampleFactory.getTestSigner();

        // Create a manifest
        const { manifestStore, manifest, previousManifest, asset } = await ManifestFactory.build(file, signer);

        await ThumbnailAssertionFactory.add(manifest, thumbnail, ThumbnailType.Claim);
        await ThumbnailAssertionFactory.add(manifest, thumbnail, ThumbnailType.Ingredient);
        await IngredientAssertionFactory.add(manifest, file, previousManifest);
        ActionAssertionFactory.add(manifest, []);
        const fileWithManifest: File = await ManifestFactory.finish(asset, manifestStore, manifest, signer, file.name);

        assert(fileWithManifest instanceof File);

        const { validationResult } = await ValidationFactory.validate(fileWithManifest);
        assert(validationResult, 'Validation result should be present');
        assert(validationResult.size > 0, 'Validation result should contain at least one entry');
        for (const [label, result] of validationResult.entries()) {
            assert(label, 'Manifest label should be present');
            assert(result.isValid !== undefined);
            assert(result.statusEntries.length > 0, `Manifest with label ${label} should have statusEntries`);
            for (const statusEntry of result.statusEntries) {
                assert(statusEntry.code !== undefined, 'Status entry code should be defined');
                assert(statusEntry.success !== undefined, 'Status entry success should be defined');
            }
        }

        assert(
            manifest.assertions?.assertions.find((assertion: Assertion) => assertion instanceof ThumbnailAssertion),
            'Manifest should contain a thumbnail assertion',
        );

        assert(
            manifest.assertions?.assertions.find((assertion: Assertion) => assertion instanceof IngredientAssertion),
            'Manifest should contain an ingredient assertion',
        );

        assert(
            manifest.assertions?.assertions.find((assertion: Assertion) => assertion instanceof ActionAssertion),
            'Manifest should contain an action assertion',
        );
    });

    it('Creating a manifest with an identity assertion', async () => {
        // Get a file. Replace it with your own file
        const file: File = ExampleFactory.getTestFile();

        // Get a signer. Replace it with your own signer
        const signer: LocalSigner = ExampleFactory.getTestSigner();

        // Get an identity signer. Replace it with your own identity signer
        const identitySigner: LocalIdentitySigner = ExampleFactory.getTestIdentitySigner();

        // Create a manifest
        const { manifestStore, manifest, asset } = await ManifestFactory.build(file, signer);

        // Add identity assertion
        await IdentityAssertionFactory.add(manifest, asset, signer, identitySigner);

        // Finish manifest
        const fileWithManifest: File = await ManifestFactory.finish(asset, manifestStore, manifest, signer, file.name);

        assert(fileWithManifest instanceof File);

        const { validationResult } = await ValidationFactory.validate(fileWithManifest);
        assert(validationResult, 'Validation result should be present');
        assert(validationResult.size > 0, 'Validation result should contain at least one entry');
        for (const [label, result] of validationResult.entries()) {
            assert(label, 'Manifest label should be present');
            assert(result.isValid !== undefined);
            assert(result.statusEntries.length > 0, `Manifest with label ${label} should have statusEntries`);
            for (const statusEntry of result.statusEntries) {
                assert(statusEntry.code !== undefined, 'Status entry code should be defined');
                assert(statusEntry.success !== undefined, 'Status entry success should be defined');
            }
        }

        assert(
            manifest.assertions?.assertions.find((assertion: Assertion) => assertion instanceof IdentityAssertion),
            'Manifest should contain an identity assertion',
        );
    });
});
