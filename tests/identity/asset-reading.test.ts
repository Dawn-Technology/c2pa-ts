/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { describe, it } from 'bun:test';
import { Asset, AssetType, JPEG } from '../../src/asset';
import { SuperBox } from '../../src/jumbf';
import { ManifestStore, ValidationResult, ValidationStatusCode } from '../../src/manifest';
import { BinaryHelper } from '../../src/util';

const baseDir = 'tests/fixtures/identity/image';

interface TestIdentityExpectations {
    /**
     * Asset class to read the file
     */
    assetType: AssetType;

    /**
     * whether the file contains a JUMBF with a C2PA Manifest
     */
    jumbf: boolean;

    /**
     * whether the file is valid according to the C2PA Manifest
     */
    valid?: boolean;

    /**
     * status codes expected in the status entries
     */
    statusCodes?: ValidationStatusCode[];
}

// test data sets with file names and expected outcomes
const testIdentityFiles: Record<string, TestIdentityExpectations> = {
    'success.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: true,
    },
    'invalid_cose_sign1.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaInvalidCoseSign1]
    },
    'invalid_cose_sign_alg.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaInvalidCoseSign1]
    },
    'missing_cose_sign_alg.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaInvalidAlg]
    },
    'invalid_content_type.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaInvalidContentType]
    },
    'invalid_content_type_assigned.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaInvalidContentType]
    },
    'missing_content_type.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaInvalidContentType]
    },
    'missing_vc.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaInvalidVerifiableCredential]
    },
    'invalid_vc.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaInvalidVerifiableCredential],
    },
    'invalid_issuer_did.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaInvalidIssuer],
    },
    'unsupported_did_method.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaDidUnsupportedMethod],
    },
    'unresolvable_did.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaDidUnavailable],
    },
    'did_doc_without_assertion_method.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaInvalidDidDocument],
    },
    'signature_mismatch.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaSignatureMismatch],
    },
    'valid_time_stamp.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaTimeStampValidated],
    },
    'invalid_time_stamp.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [
            ValidationStatusCode.IcaTimeStampInvalid,
        ],
    },
    'valid_from_missing.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaValidFromMissing],
    },
    'valid_from_in_future.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaValidFromInvalid],
    },
    'valid_from_after_time_stamp.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaValidFromInvalid],
    },
    'valid_until_in_future.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: true,
    },
    'valid_until_in_past.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaValidUntilInvalid],
    },
    'signer_payload_mismatch.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IcaSignerPayloadMismatch],
    },
    'adobe_connected_identities.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: true,
    },
    'ims_multiple_manifests.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: true,
    },
    'malformed_cbor.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IdentityCborInvalid],
    },
    // 'extra_field.jpg': {
    //     assetType: JPEG,
    //     jumbf: true,
    //     valid: true,
    // },
    'extra_assertion_claim_v1.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IdentityAssertionMismatch],
    },
    'duplicate_assertion_reference.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IdentityAssertionDuplicate],
    },
    'no_hard_binding.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IdentityHardBindingMissing],
    },
    'invalid_sig_type.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IdentitySigTypeUnknown],
    },
    'pad1_invalid.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,        
        statusCodes: [ValidationStatusCode.IdentityPadInvalid],
    },
    'pad2_invalid.jpg': {
        assetType: JPEG,
        jumbf: true,
        valid: false,
        statusCodes: [ValidationStatusCode.IdentityPadInvalid],
    },
};

describe('Functional Identity Asset Reading Tests', function () {
    for (const [filename, data] of Object.entries(testIdentityFiles)) {
        describe(`test file ${filename}`, () => {
            let buf: Buffer | undefined = undefined;
            it(`loading test file`, async () => {
                // load the file into a buffer
                buf = await fs.readFile(`${baseDir}/${filename}`);
                assert.ok(buf);
            });

            let asset: Asset | undefined = undefined;
            it(`constructing the asset`, async function () {
                if (!buf) return;

                // ensure it's a valid asset
                assert.ok(await data.assetType.canRead(buf));

                // construct the asset
                asset = await data.assetType.create(buf);
            });

            let jumbf: Uint8Array | undefined = undefined;
            it(`extract the manifest JUMBF`, async function () {
                if (!asset) return;

                // extract the C2PA manifest store in binary JUMBF format
                jumbf = await asset.getManifestJUMBF();
                if (data.jumbf) {
                    assert.ok(jumbf, 'no JUMBF found');
                } else {
                    assert.ok(jumbf === undefined, 'unexpected JUMBF found');
                }
            });

            if (data.jumbf) {
                let validationResult: ValidationResult | undefined = undefined;
                it(`validate manifest`, async function () {
                    if (!jumbf || !asset) return;

                    // deserialize the JUMBF box structure
                    const superBox = SuperBox.fromBuffer(jumbf);

                    // verify raw content
                    // Note: The raw content does not include the header (length, type),
                    // hence the offset 8.
                    assert.ok(superBox.rawContent);
                    assert.ok(
                        BinaryHelper.bufEqual(superBox.rawContent, jumbf.subarray(8)),
                        'the stored raw content is different from the stored JUMBF data',
                    );

                    // Read the manifest store from the JUMBF container
                    const manifests = ManifestStore.read(superBox);

                    // Validate the asset with the manifest
                    validationResult = await manifests.validate(asset);

                    const message =
                        data.valid ?
                            `Manifest should be valid but is not (status codes: ${validationResult.statusEntries
                                .filter((e: { success?: any }) => !e.success)
                                .map((e: { code: any }) => e.code)
                                .join(', ')})`
                        :   'Manifest is valid but should not be';
                    assert.equal(validationResult.isValid, data.valid, message);
                });

                data.statusCodes?.forEach(value => {
                    it(`check status code ${value}`, async function () {
                        if (validationResult === undefined) return;

                        assert.ok(
                            validationResult.statusEntries.some((entry: { code: any }) => entry.code === value),
                            `missing status code ${value}`,
                        );
                    });
                });
            }
        });
    }
});
