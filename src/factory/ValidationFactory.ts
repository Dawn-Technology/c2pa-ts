import { Asset, createAsset } from '../asset';
import { CawgValidationOptions } from '../cawg';
import { Signature } from '../cose';
import { SuperBox } from '../jumbf';
import { Manifest, ManifestStore, ValidationError, ValidationResult, ValidationStatusCode } from '../manifest';

export type VerifiedManifestStore = ManifestStore & {
    manifests: VerifiedManifest[];
};

export type VerifiedManifest = Manifest & {
    validationResult?: ValidationResult;
    signature: VerifiedSignature;
};

export type VerifiedSignature = Signature & {
    validationResult?: ValidationResult;
};

export class ValidationFactory {
    /**
     * Loads the asset from the provided file, reads any embedded C2PA manifest store from the JUMBF box, and validates the manifests if present.
     */
    public static async validate(
        file: File,
        options: CawgValidationOptions = {},
    ): Promise<{
        asset?: Asset;
        manifestStore?: VerifiedManifestStore;
        validationResult?: Map<string, ValidationResult> | null;
    }> {
        const asset = await createAsset(file);
        const jumbfBytes = await asset.getManifestJUMBF();

        /* no manifest found */
        if (!jumbfBytes) {
            return { asset };
        }

        const manifestStore = ManifestStore.read(SuperBox.fromBuffer(jumbfBytes)) as VerifiedManifestStore;
        const validationResult = await ValidationFactory.validateManifests(manifestStore, asset, options);
        return { asset, manifestStore, validationResult };
    }

    public static async validateManifests(
        manifestStore: VerifiedManifestStore,
        asset: Asset,
        options: CawgValidationOptions,
    ) {
        const validationResults: Map<string, ValidationResult> | null = new Map();

        const activeManifest = manifestStore.getActiveManifest();
        if (!activeManifest) {
            throw new ValidationError(
                ValidationStatusCode.ClaimCBORInvalid,
                manifestStore.sourceBox,
                'Active manifest is missing',
            );
        }

        for (const manifest of manifestStore.manifests) {
            const label = manifest.label;
            if (!label) {
                throw new ValidationError(
                    ValidationStatusCode.GeneralError,
                    manifestStore.sourceBox,
                    'The manifest is missing a label',
                );
            }

            const result = await manifest.validate(asset, options);
            manifest.validationResult = result;
            validationResults.set(label, result);
        }
        return validationResults;
    }
}
