export function isImageMimeType(file: File): boolean {
    return file.type.startsWith('image/');
}
