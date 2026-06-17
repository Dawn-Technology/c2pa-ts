import { DataHashAssertion, Manifest } from '../manifest';

export class DataHashAssertionFactory {
    /**
     * Ensures a DataHashAssertion exists in the manifest, which will be updated with the actual asset hash before signing.
     * This assertion provides a hard binding between the manifest and the asset content.
     */
    public static ensure(manifest: Manifest): DataHashAssertion {
        // Get or create a data hash assertion (hard binding)
        let dataHashAssertion;
        if (manifest.assertions?.getHardBindings()?.length) {
            return manifest.assertions?.getHardBindings()[0] as DataHashAssertion;
        } else {
            dataHashAssertion = DataHashAssertion.create('SHA-256');
            manifest.addAssertion(dataHashAssertion);
            return dataHashAssertion;
        }
    }
}
