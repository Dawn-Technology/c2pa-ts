/**
 * Identity Signer Interface
 * Defines the signer contract for CAWG identity assertions
 *
 * @module cawg/identity-signer
 */
import { NamedActorRole, SignatureType, VerifiedIdentity } from '../cawg';
import { Signer } from '../cose/Signer';

/**
 * Interface for signers that can produce CAWG identity assertion signatures
 *
 * Extends the base COSE signer contract with identity metadata required to
 * build identity assertions and ICA credentials.
 */
export interface IdentitySigner extends Pick<Signer, 'sign' | 'algorithm'> {
    /** Verified identity record(s) associated with the signer */
    verifiedIdentity: VerifiedIdentity | VerifiedIdentity[];
    /** Named actor role(s) for the signer in the C2PA asset lifecycle */
    roles: NamedActorRole[];
    /** Signature profile used for the identity assertion */
    signatureType: SignatureType;
    /** Issuer DID used for ICA credentials */
    issuerDid: Promise<string>;
}
