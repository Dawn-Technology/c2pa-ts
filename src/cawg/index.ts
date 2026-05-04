/**
 * CAWG Identity Assertion Module
 *
 * Implementation of the Creator Assertions Working Group (CAWG) Identity Assertion
 * specification version 1.2 (DIF Ratified - December 15, 2025)
 *
 * This module provides comprehensive support for creating and validating identity
 * assertions in C2PA manifests, allowing named actors to cryptographically bind
 * their identity to digital assets.
 */

// Type definitions
export * from './types.js';
// Utility functions
export * from './utils.js';

// Validator functions
export { validateIdentityAssertion, isWellFormedIdentityAssertion } from './validator.js';

// Did resolver
export { didResolver } from './did-resolver.js';

// Identity Claims Aggregation support
export { createIcaCredential, validateIcaCredential } from './identity-claims-aggregation.js';

/**
 * CAWG specification version implemented by this module
 */
export const CAWG_VERSION = '1.2';

/**
 * CAWG specification release date
 */
export const CAWG_RELEASE_DATE = '2025-12-15';

/**
 * Default identity assertion label
 */
export const DEFAULT_ASSERTION_LABEL = 'cawg.identity';

/**
 * Maximum length for text strings in CAWG structures
 */
export const MAX_TSTR_LENGTH = 4096;
