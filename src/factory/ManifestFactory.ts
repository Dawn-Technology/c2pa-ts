import { Asset, createAsset } from '../asset';
import { LocalSigner } from '../cose';
import { SuperBox } from '../jumbf';
import { ClaimVersion, Manifest, ManifestStore } from '../manifest';
import { LocalTimestampProvider } from '../rfc3161';
import { DataHashAssertionFactory } from './DataHashAssertionFactory';

export class ManifestFactory {
    /**
     * Loads the asset from the provided file, checks for existing C2PA manifest in a JUMBF box, and creates a new manifest if none exists.
     */
    public static async buildManifest(file: File, signer: LocalSigner) {
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
     */
    public static async signManifest(
        asset: Asset,
        manifestStore: ManifestStore,
        manifest: Manifest,
        signer: LocalSigner,
        timestampProvider: LocalTimestampProvider,
        fileName: string,
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
}
