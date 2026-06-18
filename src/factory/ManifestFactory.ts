import { Asset, createAsset } from '../asset';
import { LocalSigner } from '../cose';
import { SuperBox } from '../jumbf';
import { ClaimVersion, Manifest, ManifestStore } from '../manifest';
import { LocalTimestampProvider } from '../rfc3161';
import { DataHashAssertionFactory } from './DataHashAssertionFactory';

export class ManifestFactory {
    /**
     * Loads the asset from the provided file, checks for existing C2PA manifest in a JUMBF box, and creates a new manifest if none exists.
     * If a manifest already exists, it will be loaded and returned along with the asset and manifest store.
     * @param file - The input file representing the asset to be signed
     * @param signer - The LocalSigner used for manifest creation
     * @returns An object containing the loaded asset, manifest store, previous manifest (if any), and the new manifest
     */
    public static async build(file: File, signer: LocalSigner) {
        const instanceID = crypto.randomUUID();
        const asset = await createAsset(file);
        const jumbfBytes = await asset.getManifestJUMBF(); // depends on asset class

        let manifestStore: ManifestStore;
        let previousManifest: Manifest | undefined;
        if (jumbfBytes) {
            const superBox = SuperBox.fromBuffer(jumbfBytes);

            manifestStore = ManifestStore.read(superBox);
            previousManifest = manifestStore.getActiveManifest();
        } else {
            manifestStore = new ManifestStore();
        }

        const manifest: Manifest = manifestStore.createManifest({
            claimVersion: ClaimVersion.V2,
            assetFormat: file.type,
            instanceID,
            defaultHashAlgorithm: 'SHA-256',
            signer,
        });

        return { asset, manifestStore, previousManifest, manifest };
    }

    /**
     * Signs the manifest (ensures manifest space, updates the hard binding, and creates the signature).
     * Then writes the manifest JUMBF box to the asset and exports the modified file with the embedded manifest.
     * @param asset - The asset to which the manifest will be bound
     * @param manifestStore - The manifest store containing the manifest to sign
     * @param manifest - The manifest to sign
     * @param signer - The LocalSigner used to create the signature
     * @param timestampProvider - The LocalTimestampProvider used to timestamp the signature
     * @param fileName - The name of the output file containing the signed manifest
     * @returns A File containing the modified asset data with the embedded C2PA manifest
     */
    public static async finish(
        asset: Asset,
        manifestStore: ManifestStore,
        manifest: Manifest,
        signer: LocalSigner,
        fileName: string,
        timestampProvider?: LocalTimestampProvider,
    ): Promise<File> {
        // Get or create a data hash assertion (hard binding)
        const dataHashAssertion = DataHashAssertionFactory.ensure(manifest);

        // make space in the asset
        await asset.ensureManifestSpace(manifestStore.measureSize());

        // update the hard binding
        await dataHashAssertion.updateWithAsset(asset);

        // create the signature
        await manifest.sign(signer, timestampProvider);

        // write the JUMBF box to the asset
        await asset.writeManifestJUMBF(manifestStore.getBytes());

        // export the modified file which now includes the manifest
        const bytes = await asset.getDataRange();

        return new File([new Uint8Array(bytes)], fileName, { type: asset.mimeType || 'application/octet-stream' });
    }

    /**
     * Builds a manifest for the given file, signs it, and embeds it into the file.
     * @param file - The file to which the manifest will be bound
     * @param signer - The LocalSigner used to create the signature
     * @param timestampProvider - The LocalTimestampProvider used to timestamp the signature
     * @returns A File containing the modified asset data with the embedded C2PA manifest
     */
    public static async buildAndFinish(
        file: File,
        signer: LocalSigner,
        timestampProvider?: LocalTimestampProvider,
    ): Promise<File> {
        const { asset, manifestStore, manifest } = await this.build(file, signer);
        return this.finish(asset, manifestStore, manifest, signer, file.name, timestampProvider);
    }
}
