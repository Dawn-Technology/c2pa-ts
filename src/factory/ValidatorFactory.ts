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

export class ValidatorFactory {
    /**
     * Loads the asset from the provided file, checks for existing C2PA manifest in a JUMBF box, and creates a new manifest if none exists.
     */
    public static async validate(
        file: File,
        options: CawgValidationOptions = { cawg: {} },
    ): Promise<{
        asset?: Asset;
        manifestStore?: VerifiedManifestStore;
        manifestValidationResults?: Map<string, ValidationResult> | null;
    }> {
        const asset = await createAsset(file);
        const jumbfBytes = await asset.getManifestJUMBF();

        /* no manifest found */
        if (!jumbfBytes) {
            return { asset };
        }

        const manifestStore = ManifestStore.read(SuperBox.fromBuffer(jumbfBytes)) as VerifiedManifestStore;
        const manifestValidationResults = await ValidatorFactory.validateManifests(manifestStore, asset, options);
        return { asset, manifestStore, manifestValidationResults };
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
