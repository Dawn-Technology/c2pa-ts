import { Manifest, ThumbnailAssertion, ThumbnailType } from '../manifest';
import { isImageMimeType } from './FactoryHelper';

export class ThumbnailAssertionFactory {
    /**
     * Adds a ThumbnailAssertion to the manifest with the thumbnail data.
     */
    public static async add(
        manifest: Manifest,
        thumbnail: File,
        type: ThumbnailType,
    ): Promise<ThumbnailAssertion | undefined> {
        if (!isImageMimeType(thumbnail)) {
            // File type is not an image, skipping thumbnail generation
            return;
        }
        const fileExtension = thumbnail.type.replace(/.*\//, '');
        const thumbnailBytes = new Uint8Array(await thumbnail.arrayBuffer());
        const thumbnailAssertion = ThumbnailAssertion.create(fileExtension, thumbnailBytes, type);
        manifest.addAssertion(thumbnailAssertion);
        return thumbnailAssertion;
    }
}
