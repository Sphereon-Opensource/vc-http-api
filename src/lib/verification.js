import {verifyCredentialWithRevocation} from './revocation';
import revocation from '../api/revocation';
import {documentLoader} from './credential';
import {resolver} from './did';
import VerificationError from './error/VerificationError';
import {Ed25519KeyPair, RSAKeyPair} from 'crypto-ld';
import {suites} from 'jsonld-signatures';
import vcjs from 'vc-js';
import InvalidRequestError from './error/InvalidRequestError';
import {parseVcJsVerificationError} from './util';
import base58 from 'bs58';

const VERIFICATION_METHOD_KEY_EXPANDED = 'https://w3id.org/security#verificationMethod';

const verifyCredential = async (verifiableCredential) => {
    const verify = await _getVerificationFunction(verifiableCredential);
    return verify(verifiableCredential)
        .then(result => {
            if (result.verified) {
                let checks = ['proof'];
                if (result.revocation) {
                    checks = [...checks, 'revocation']
                }
                return {
                    checks,
                    warnings: [],
                    errors: [],
                };
            }
            parseVcJsVerificationError(result.error);
        });
};

const getSuite = async proof => {
    const verificationMethod = _getVerificationMethod(proof);
    const did = resolver.extractDidFromVerificationMethod(verificationMethod);
    return resolver.getDidDocument(did).then(didDocument => {
        const key = getKeyForVerificationMethod(verificationMethod, didDocument);
        if (Array.isArray(key.type) && key.type.includes('RSAVerificationKey')) {
            return _getRsaSuite(key);
        } else {
            return _getEd25519Suite(key);
        }

    });
};

const verifyPresentation = async (verifiablePresentation, challenge) => {
    const {proof} = verifiablePresentation;
    //attempt to fetch did document for credentials
    const {verifiableCredential} = verifiablePresentation;
    let credentialSuites = [];
    let revocationChecks = [];
    if (verifiableCredential && Array.isArray(verifiableCredential)) {
        credentialSuites = await Promise.all(verifiableCredential
            .filter(vc => !!vc.proof)
            .map(vc => getSuite(vc.proof)));
        revocationChecks = await Promise.all(
            verifiableCredential
                .filter(vc => !!vc.credentialStatus)
                .map(vc => verifyCredentialWithRevocation(vc))
        );
    }

    //attempt to fetch suite for presentation
    const presentationSuite = await getSuite(proof);
    return vcjs.verify({
        presentation: verifiablePresentation,
        suite: [...credentialSuites, presentationSuite],
        documentLoader,
        challenge
    }).then(result => {
        let checks = ['proof'];
        if (revocationChecks.length) {
            if (revocationChecks.every(result => result.revocation)) {
                checks = [...checks, 'revocation'];
            } else {
                throw new VerificationError('One or more credentials in the presentation has been revoked');
            }
        }
        if (result.verified) {
            return {
                checks,
                warnings: [],
                errors: [],
            };
        } else {
            parseVcJsVerificationError(result.error);
        }
    });
}

const getKeyForVerificationMethod = (verificationMethod, didDocument) => {
    if (didDocument.publicKey) {
        const {publicKey} = didDocument;
        const key = publicKey.find(pk => pk.id === verificationMethod);
        if (key) {
            return key;
        }
    }
    if (didDocument.assertionMethod) {
        const {assertionMethod} = didDocument;
        const key = assertionMethod.find(method => method.id === verificationMethod);
        if (key) {
            return key;
        }
    }
    if (didDocument.authentication) {
        const {authentication} = didDocument;
        const key = authentication.find(method => method.id === verificationMethod);
        if (key) {
            return key;
        }
    }
    throw new InvalidRequestError('Could not find verification method in DID document');
};

const _getVerificationFunction = async (vc) => {
    if (vc.credentialStatus) {
        return new Promise(resolve => resolve(verifyCredentialWithRevocation));
    }
    const {proof} = vc;
    const suite = await getSuite(proof);
    return credential => vcjs.verifyCredential({credential, suite, documentLoader})
        .catch(parseVcJsVerificationError);
};

const _publicKeyBase58ToPem = publcKeyBase58 => {
    const base64PublicKey = Buffer.from(base58.decode(publcKeyBase58)).toString('base64');
    return '-----BEGIN PUBLIC KEY-----\r\n' + base64PublicKey + '\r\n-----END PUBLIC KEY-----\r\n';
};

const _getVerificationMethod = proof => {
    let verificationMethod = proof.verificationMethod || proof[VERIFICATION_METHOD_KEY_EXPANDED];
    if(typeof verificationMethod === 'object'){
        verificationMethod =  verificationMethod.id;
    }
    if (!verificationMethod) {
        throw new InvalidRequestError('Invalid proof!');
    }
    return verificationMethod
};

const _getRsaSuite = key => {
    let publicKeyPem;
    if (!key.publicKeyPem) {
        publicKeyPem = _publicKeyBase58ToPem(key.publicKeyBase58);
    } else {
        publicKeyPem = key.publicKeyPem;
    }
    const keyPair = new RSAKeyPair({publicKeyPem});
    keyPair.id = key.id;
    keyPair.controller = key.controller;
    return new suites.RsaSignature2018({
        verificationMethod: keyPair.id,
        key: keyPair
    });
};

const _getEd25519Suite = key => {
    const importKey = new Ed25519KeyPair({...key});
    return new suites.Ed25519Signature2018({
        verificationMethod: key.id,
        key: importKey,
    });
}

export {verifyCredential, verifyPresentation, getSuite};
