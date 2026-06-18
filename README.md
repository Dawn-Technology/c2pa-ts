<a id="readme-top"></a>

# c2pa-ts

[![Tests](https://github.com/Dawn-Technology/c2pa-ts/actions/workflows/ci.yaml/badge.svg)](https://github.com/Dawn-Technology/c2pa-ts/actions/workflows/ci.yaml)

## About

`c2pa-ts` is a pure TypeScript implementation of [Coalition for Content Provenance and Authenticity (C2PA)](https://c2pa.org/) according to [specification version 2.1](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html).

It does not use any native binaries or WebAssembly and is therefore truly platform independent. In modern browsers as well as Node.js it should run out of the box. In mobile apps or other environments lacking browser APIs, some external code may be necessary (see [below](#usage-in-constrained-environments) for details).

This repository is a fork of the [`c2pa-ts`](https://github.com/TrustNXT/c2pa-ts) library. That  library is developed and curated by  of [TrustNXT](https://trustnxt.com) in Hamburg, Germany and licensed under the Apache 2.0 License. 

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Current status

This library is used for a pilot and not fully functional yet. Proceed with caution!

### Overall functionality

- :white_check_mark: Reading manifests
- :white_check_mark: Validating manifests
- :white_check_mark: Creating manifests

:information_source: On C2PA versions: The library is targeted at C2PA specification 2.1, however data structures from older versions of the specification are also supported for backwards compatibility.

:information_source: On CAWG versions: The library is targeted at CAWG specification 1.2.

### Asset file formats

- :white_check_mark: JPEG
- :white_check_mark: PNG
- :white_check_mark: HEIC/HEIF
- :white_check_mark: MP3
- :white_check_mark: MP4
- :x: GIF
- :x: TIFF
- :x: WebP
- :x: JPEG XL

### Supported assertions

- :white_check_mark: Data Hash
- :white_check_mark: BMFF-Based Hash (v2 and v3)
- :x: General Boxes Hash
- :white_check_mark: Thumbnail
- :white_check_mark: Actions (except action templates and metadata)
- :white_check_mark: Ingredient (v2 and v3)
- :white_check_mark: Metadata (specialized, common, generic, and CAWG variants)
- :white_check_mark: Creative Work
- :white_check_mark: Training and Data Mining (C2PA and CAWG variants)
- :white_check_mark: CAWG Identity

### JUMBF boxes

- :white_check_mark: CBOR boxes
- :white_check_mark: JSON boxes
- :white_check_mark: Codestream boxes
- :white_check_mark: Embedded file boxes
- :white_check_mark: UUID boxes
- :white_check_mark: C2PA salt boxes
- :x: Compressed boxes

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage examples

<details><summary>Validate a file</summary>

```typescript
import { ExampleFactory, ValidationFactory } from '@dawn-technology/c2pa-ts/factory';

// Get a file. Replace it with your own file
const file: File = ExampleFactory.getTestFile();

// Validate the file
const { validationResult } = await ValidationFactory.validate(file);
console.log('Validation result', validationResult);
```
</details>

<details><summary>Creating a manifest</summary>

```typescript
import { LocalSigner } from '@dawn-technology/c2pa-ts/cose';
import { ExampleFactory, ManifestFactory } from '@dawn-technology/c2pa-ts/factory';

// Get a file. Replace it with your own file
const file: File = ExampleFactory.getTestFile();

// Get a signer. Replace it with your own signer
const signer: LocalSigner = ExampleFactory.getTestSigner();

// Apply C2PA on a file and return the new file
const fileWithManifest: File = await ManifestFactory.buildAndFinish(file, signer);
```
</details>

<details><summary>Creating a manifest with an action, thumbnail and ingredient assertion</summary>

```typescript
import { LocalSigner } from '@dawn-technology/c2pa-ts/cose';
import { ActionAssertionFactory, ExampleFactory, IngredientAssertionFactory, ManifestFactory, ThumbnailAssertionFactory } from '@dawn-technology/c2pa-ts/factory';
import { ActionType, ThumbnailType } from '@dawn-technology/c2pa-ts/manifest';

// Get a file. Replace it with your own file
const file: File = ExampleFactory.getTestFile();

// Get a thumbnail. Replace it with your own thumbnail
const thumbnail: File = ExampleFactory.getTestFile();

// Get a signer. Replace it with your own signer
const signer: LocalSigner = ExampleFactory.getTestSigner();

// Create a manifest
const { manifestStore, manifest, previousManifest, asset } = await ManifestFactory.build(file, signer);

// Add assertions
await ThumbnailAssertionFactory.add(manifest, thumbnail, ThumbnailType.Claim);
await ThumbnailAssertionFactory.add(manifest, thumbnail, ThumbnailType.Ingredient);
await IngredientAssertionFactory.add(manifest, file, previousManifest);
ActionAssertionFactory.add(manifest, [ActionType.C2paOpened]);

// Finish manifest
const fileWithManifest: File = await ManifestFactory.finish(asset, manifestStore, manifest, signer, file.name);
```
</details>

<details><summary>Creating a manifest with an identity assertion</summary>

```typescript
import { LocalIdentitySigner } from '@dawn-technology/c2pa-ts/cawg';
import { LocalSigner } from '@dawn-technology/c2pa-ts/cose';
import { ExampleFactory, IdentityAssertionFactory, ManifestFactory } from '@dawn-technology/c2pa-ts/factory';

// Get a file. Replace it with your own file
const file: File = ExampleFactory.getTestFile();

// Get a signer. Replace it with your own signer
const signer: LocalSigner = ExampleFactory.getTestSigner();

// Get an identity signer. Replace it with your own identity signer
const identitySigner: LocalIdentitySigner = ExampleFactory.getTestIdentitySigner();

// Create a manifest
const { manifestStore, manifest, asset } = await ManifestFactory.build(file, signer);

// Add identity assertions
await IdentityAssertionFactory.add(manifest, asset, signer, identitySigner);

// Finish manifest
const fileWithManifest: File = await ManifestFactory.finish(asset, manifestStore, manifest, signer, file.name);
```
</details>

<details><summary>Reading and validating a manifest in a Node.js environment</summary>

```typescript
import * as fs from 'node:fs/promises';
import { MalformedContentError } from '@dawn-technology/c2pa-ts';
import { Asset, createAsset } from '@dawn-technology/c2pa-ts/c2pa-ts/asset';
import { SuperBox } from '@dawn-technology/c2pa-ts/c2pa-ts/jumbf';
import { ManifestStore, ValidationResult, ValidationStatusCode } from '@dawn-technology/c2pa-ts/c2pa-ts/manifest';

if (process.argv.length < 3) {
    console.error('Missing filename');
    process.exit(1);
}

const buf = await fs.readFile(process.argv[2]);

// Read the asset file and dump some information about its structure
let asset: Asset;
try {
    asset = await createAsset(buf);
} catch {
    console.error('Unknown file format');
    process.exit(1);
}
console.log(asset.dumpInfo());

// Extract the C2PA manifest store in binary JUMBF format
const jumbf = await asset.getManifestJUMBF();

if (jumbf) {
    let validationResult: ValidationResult;

    try {
        // Deserialize the JUMBF box structure
        const superBox = SuperBox.fromBuffer(jumbf);
        console.log('JUMBF structure:');
        console.log(superBox.toString());

        // Read the manifest store from the JUMBF container
        const manifests = ManifestStore.read(superBox);

        // Validate the active manifest
        validationResult = await manifests.validate(asset);
    } catch (e) {
        // Gracefully handle any exceptions to make sure we get a well-formed validation result
        validationResult = ValidationResult.fromError(e as Error);
    }

    console.log('Validation result', validationResult);
}
```
</details>

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Common issues

### `error: tsyringe requires a reflect polyfill`

This error message comes from a dependency of c2pa-ts, `@peculiar/x509`, requiring a Reflect API Polyfill. The fix is to simply add one of the recommended polyfill packages to your project and add an import to the top of your code. See [the `@peculiar/x509` repository](https://github.com/PeculiarVentures/x509?tab=readme-ov-file#%EF%B8%8F-reflect-polyfill-required) for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage in constrained environments

Usage with JavaScript engines that lack WebCrypto and other browser APIs (such as JavaScriptCore on iOS) is entirely possible but will require some additional code. In particular, a custom `CryptoProvider` will need to be created and some polyfills might be required.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## License

Distributed under the Apache 2.0 License. See `LICENSE.md` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Acknowledgments

The following resources were helpful during creation of this library:

- [c2pa-rs](https://github.com/contentauth/c2pa-rs/)
- [public-testfiles](https://github.com/c2pa-org/public-testfiles/)
- [CAI Discord server](https://discord.gg/CAI)
- [@peculiar/x509](https://github.com/PeculiarVentures/x509)
- [PKI.js](https://github.com/PeculiarVentures/PKI.js)
- [ASN1.js](https://github.com/PeculiarVentures/ASN1.js)
- [MIPAMS JPEG Systems](https://github.com/nickft/mipams-jpeg-systems)
- [cbor-x](https://github.com/kriszyp/cbor-x)
- [bun](https://bun.sh)
- [typed-binary](https://github.com/iwoplaza/typed-binary)

Thank you for providing them and keeping open source alive!

<p align="right">(<a href="#readme-top">back to top</a>)</p>
