import {resolver} from '../did';
import documentLoader from './documentLoader';
import InvalidCredentialStructureError from '../error/InvalidCredentialStructureError';
import factomDid from '../../resources/did/factomDid.json';
import veresOneDid from '../../resources/did/veresOneDid.json';
import InvalidIssuanceOptionsError from '../error/InvalidIssuanceOptionsError';

const AllowedProofPurposes = Object.freeze(['assertionMethod']);
const AllowedIssuers = Object.freeze([factomDid.identity.did, veresOneDid.did]);
const W3C_VC_CONTEXT_V1 = 'https://www.w3.org/2018/credentials/v1';
const W3C_VC_TYPE = 'VerifiableCredential';
const VERIFICATION_METHOD_KEY_EXPANDED = 'https://w3id.org/security#verificationMethod';
const PROOF_PURPOSE_KEY_EXPANDED = 'https://w3id.org/security#proofPurpose';
const ASSERTION_METHOD_VALUE_EXPANDED = Object.freeze({
    "id": "https://w3id.org/security#assertionMethod"
});

const verifyCredentialStructure = (verifiableCredential) => {
    if (!verifiableCredential) {
        throw new InvalidCredentialStructureError('No verifiableCredential in request.');
    }
    if (!verifiableCredential.proof) {
        throw new InvalidCredentialStructureError('Verifiable credential requires proof.');
    }
    const {proof} = verifiableCredential;
    if (!proof.verificationMethod && !proof[VERIFICATION_METHOD_KEY_EXPANDED]) {
        throw new InvalidCredentialStructureError('Credential proof verification method not found.');
    }

    if (!proof.proofPurpose && !proof[PROOF_PURPOSE_KEY_EXPANDED]) {
        throw new InvalidCredentialStructureError('Credential proof requires proof purpose field.');
    }

    if (typeof proof.proofPurpose == 'string' && proof.proofPurpose !== 'assertionMethod') {
        const message = `Expected proof.proofPurpose to be assertionMethod. Got: ${proof.proofPurpose}`;
        throw new InvalidCredentialStructureError(message);
    }

    if (!proof.created) {
        throw new InvalidCredentialStructureError('Proof must contain created field.');
    }
};

const assertValidIssuanceCredential = credential => {
    if (!credential) {
        throw new InvalidCredentialStructureError('Request must contain a credential');
    } else if (!credential['@context']) {
        throw new InvalidCredentialStructureError('Credential must contain a context');
    } else if (!credential.issuer) {
        throw new InvalidCredentialStructureError('Credential must have an issuer');
    } else if (credential['@context'][0] !== W3C_VC_CONTEXT_V1) {
        const message = `First value in credential context must be: ${W3C_VC_CONTEXT_V1} 
        but got: ${credential['@context'][0]}`;
        throw new InvalidCredentialStructureError(message)
    }
};

const getRequestedIssuer = options => {
    // if no issuer specified, issue on factom did
    if (!options) {
        return new Promise(resolve => resolve(factomDid.identity.did));
    }

    if (options.proofPurpose && !AllowedProofPurposes.includes(options.proofPurpose)) {
        const message = `Proof purpose not supported. Expected one of ${AllowedProofPurposes}
        but got: ${options.proofPurpose}`;
        return new Promise((_, reject) => reject(new InvalidIssuanceOptionsError(message)));
    }

    // if issuer specified
    if (options.issuer && AllowedIssuers.includes(options.issuer)) {
        if (options.assertionMethod) {
            return resolver.validateAssertionMethod(options.assertionMethod, options.issuer);
        }
        return options.issuer;
    }

    if (options.assertionMethod) {
        return resolver.validateAssertionMethod(options.assertionMethod);
    }

    throw new InvalidIssuanceOptionsError('Invalid options');
}

export {
    verifyCredentialStructure,
    assertValidIssuanceCredential,
    getRequestedIssuer,
    documentLoader,
    W3C_VC_TYPE,
    W3C_VC_CONTEXT_V1
};
