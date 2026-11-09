import assert from 'node:assert/strict';
import { type X509Certificate } from '@peculiar/x509';
import { afterEach, beforeEach, describe, it } from 'bun:test';
import { PKIStatus, PKIStatusInfo, TimeStampReq, TimeStampResp } from 'pkijs';
import { CoseAlgorithmIdentifier, Signer } from '../src/cose';
import { Signature } from '../src/cose/Signature';
import { SigStructure } from '../src/cose/SigStructure';
import { CoseSignature } from '../src/cose/types';
import { CBORBox } from '../src/jumbf';
import { ValidationStatusCode } from '../src/manifest';
import { LocalTimestampProvider, TimestampProvider, WebTimestampProvider } from '../src/rfc3161';
import { loadTestCertificate } from './utils/testCertificates';

describe('Timestamp Tests', () => {
    let signature: Signature;
    let mockTimestampProvider: LocalTimestampProvider;
    let localSigner: Signer;
    let x509Certificate: X509Certificate;

    beforeEach(async () => {
        const { signer, timestampProvider } = await loadTestCertificate({
            name: 'ES256 sample certificate',
            certificateFile: 'tests/fixtures/sample_es256.pem',
            privateKeyFile: 'tests/fixtures/sample_es256.key',
            algorithm: CoseAlgorithmIdentifier.ES256,
        });

        localSigner = signer;
        x509Certificate = localSigner.certificate;
        mockTimestampProvider = timestampProvider;

        // Create protected bucket with algorithm and certificate chain
        const protectedBucket = {
            1: CoseAlgorithmIdentifier.ES256,
            33: [x509Certificate.rawData],
        };
        const protectedBytes = CBORBox.encoder.encode(protectedBucket);

        // Create and sign the payload
        const payload = new Uint8Array([1, 2, 3, 4]);
        const sigStructure = new SigStructure('Signature1', protectedBytes, payload);
        const toBeSigned = sigStructure.encode();
        const mockSignature = await signer.sign(toBeSigned);

        const mockCoseSignature: CoseSignature = [
            protectedBytes,
            {}, // Unprotected header
            null, // External AAD
            mockSignature,
        ];

        signature = Signature.readFromJUMBFData(mockCoseSignature);
    });

    describe('Timestamp Validation', () => {
        it('should validate timestamp with correct hash algorithm', async () => {
            const payload = new Uint8Array([1, 2, 3, 4]);
            await signature.sign(localSigner, payload, mockTimestampProvider);

            const result = await signature.validate(payload);

            assert.ok(result.statusEntries.some(e => e.code === ValidationStatusCode.TimeStampTrusted));
            assert.ok(result.isValid);
        });

        it('should validate timestamp within certificate validity period', async () => {
            const payload = new Uint8Array([1, 2, 3, 4]);
            await signature.sign(localSigner, payload, mockTimestampProvider);

            const result = await signature.validate(payload);

            assert.ok(result.statusEntries.some(e => e.code === ValidationStatusCode.SigningCredentialTrusted));
            assert.ok(result.isValid);
        });

        it('should validate timestamp signature', async () => {
            const payload = new Uint8Array([1, 2, 3, 4]);
            await signature.sign(localSigner, payload, mockTimestampProvider);

            const result = await signature.validate(payload);

            assert.ok(result.statusEntries.some(e => e.code === ValidationStatusCode.ClaimSignatureValidated));
            assert.ok(result.isValid);
        });

        it('should handle missing timestamp provider', async () => {
            const payload = new Uint8Array([1, 2, 3, 4]);
            await signature.sign(localSigner, payload);

            const result = await signature.validate(payload);

            assert.ok(!result.statusEntries.some(e => e.code === ValidationStatusCode.TimeStampTrusted));
        });

        it('should handle multiple timestamp tokens', async () => {
            const payload = new Uint8Array([1, 2, 3, 4]);
            await signature.sign(localSigner, payload, mockTimestampProvider);
            await signature.sign(localSigner, payload, mockTimestampProvider);

            const result = await signature.validate(payload);

            assert.ok(result.statusEntries.some(e => e.code === ValidationStatusCode.TimeStampTrusted));
            assert.ok(result.statusEntries.some(e => e.code === ValidationStatusCode.ClaimSignatureValidated));
            assert.ok(result.isValid);
        });

        it('should validate timestamp matches signed content', async () => {
            const payload = new Uint8Array([1, 2, 3, 4]);
            await signature.sign(localSigner, payload, mockTimestampProvider);

            const differentPayload = new Uint8Array([5, 6, 7, 8]);
            const result = await signature.validate(differentPayload);

            assert.ok(result.statusEntries.some(e => e.code === ValidationStatusCode.ClaimSignatureMismatch));
            assert.ok(!result.isValid);
        });

        it('should detect corrupted timestamp tokens', async () => {
            const payload = new Uint8Array([1, 2, 3, 4]);

            await signature.sign(localSigner, payload, mockTimestampProvider);

            const corruptedBucket = {
                1: CoseAlgorithmIdentifier.ES256,
                33: [x509Certificate.rawData],
                sigTst: {
                    tstTokens: [{ val: new Uint8Array([0x30, 0x00]) }], // Invalid ASN.1
                },
            };
            signature.rawProtectedBucket = CBORBox.encoder.encode(corruptedBucket);

            const result = await signature.validate(payload);

            assert.ok(result.statusEntries.some(e => e.code === ValidationStatusCode.TimeStampMismatch));
            assert.ok(!result.isValid);
        });
    });

    describe('Timestamp Failures', () => {
        const payload = new Uint8Array([1, 2, 3, 4]);
        const originalFetch = globalThis.fetch;

        afterEach(() => {
            globalThis.fetch = originalFetch;
        });

        it('should throw when the provider returns no response', async () => {
            const provider: TimestampProvider = { getSignedTimestamp: async () => undefined };

            await assert.rejects(
                () => signature.sign(localSigner, payload, provider),
                /Timestamp authority did not grant a timestamp/,
            );
        });

        it('should throw when the timestamp authority rejects the request', async () => {
            const provider: TimestampProvider = {
                getSignedTimestamp: async () =>
                    new TimeStampResp({ status: new PKIStatusInfo({ status: PKIStatus.rejection }) }),
            };

            await assert.rejects(
                () => signature.sign(localSigner, payload, provider),
                /Timestamp authority did not grant a timestamp/,
            );
        });

        it('should throw when the response is granted but contains no token', async () => {
            const provider: TimestampProvider = {
                getSignedTimestamp: async () =>
                    new TimeStampResp({ status: new PKIStatusInfo({ status: PKIStatus.granted }) }),
            };

            await assert.rejects(
                () => signature.sign(localSigner, payload, provider),
                /Timestamp authority did not grant a timestamp/,
            );
        });

        it('should throw when WebTimestampProvider receives an HTTP error', async () => {
            globalThis.fetch = (async () => new Response('unavailable', { status: 503 })) as unknown as typeof fetch;

            await assert.rejects(
                () => signature.sign(localSigner, payload, new WebTimestampProvider('https://tsa.example/timestamp')),
                /Timestamp authority responded with HTTP 503/,
            );
        });

        it('should add a timestamp through WebTimestampProvider', async () => {
            globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
                const request = TimeStampReq.fromBER(init?.body as ArrayBuffer);
                const response = await mockTimestampProvider.getSignedTimestamp(request);
                return new Response(response.toSchema().toBER());
            }) as unknown as typeof fetch;

            await signature.sign(localSigner, payload, new WebTimestampProvider('https://tsa.example/timestamp'));

            const result = await signature.validate(payload);
            assert.ok(result.statusEntries.some(e => e.code === ValidationStatusCode.TimeStampTrusted));
            assert.ok(signature.timestamp instanceof Date);
        });
    });
});
