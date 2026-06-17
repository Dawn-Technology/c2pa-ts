import { parse } from 'exifr';
import { IngredientAssertion, Manifest, RelationshipType } from '../manifest';
import { isImageMimeType } from './FactoryHelper';

export class IngredientAssertionFactory {
    /**
     * Builds an IngredientAssertion for the original asset file, including XMP metadata if available, and adds it to the manifest.
     * If a previous manifest exists, it links to it using the c2pa_manifest property.
     * The IngredientAssertion is also linked to the ActionAssertion via a ParentOf relationship.
     */
    public static async add(
        manifest: Manifest,
        file: File,
        previousManifest: Manifest | undefined,
    ): Promise<IngredientAssertion> {
        const { instanceID: xmpInstanceId, documentID: xmpDocumentID } =
            await IngredientAssertionFactory.getImageXmpIdentifiers(file);

        const ingredientAssertion = IngredientAssertion.create(
            file.name,
            file.type,
            xmpInstanceId ?? `urn:uuid:${crypto.randomUUID()}`,
            xmpDocumentID,
        );
        ingredientAssertion.relationship = RelationshipType.ParentOf;

        if (isImageMimeType(file)) {
            ingredientAssertion.thumbnail = manifest.createHashedReference(
                `c2pa.assertions/c2pa.thumbnail.ingredient.${file.type.replace(/.*\//, '')}`,
            );
        }

        if (previousManifest) {
            ingredientAssertion.instanceID = previousManifest.claim?.instanceID;
            ingredientAssertion.c2pa_manifest = manifest.createHashedReference(
                `/c2pa/${previousManifest.label}/c2pa.claim.v2`,
            );
        }

        manifest.addAssertion(ingredientAssertion);
        return ingredientAssertion;
    }

    private static async getImageXmpIdentifiers(
        input: Parameters<typeof parse>[0],
    ): Promise<{ instanceID: string | undefined; documentID: string | undefined }> {
        try {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const metadata: { InstanceID: string | undefined; DocumentID: string | undefined } = await parse(input, {
                xmp: true,
                tiff: false,
                exif: false,
                icc: false,
            });

            return {
                instanceID: metadata.InstanceID ? metadata.InstanceID.replace('xmp.iid:', 'xmp:iid:') : undefined,
                documentID: metadata.DocumentID ? metadata.DocumentID.replace('xmp.did:', 'xmp:did:') : undefined,
            };
        } catch {
            return { instanceID: undefined, documentID: undefined };
        }
    }
}
