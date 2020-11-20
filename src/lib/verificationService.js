import {verifyCredentialWithRevocation} from "./revocation";
import revocation from "../api/revocation";

const {getDidDocument} = require('./did/resolver');
const {extractDidFromVerificationMethod} = require('./did/resolver');
const {Ed25519KeyPair, suites: {Ed25519Signature2018}} = require('jsonld-signatures');
const {documentLoader} = require('./customDocumentLoader');
const vcjs = require('vc-js');

async function verifyCredential(verifiableCredential) {
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
            if (result.error) {
                throw result.error;
            }
            throw {code: 500, message: 'Could not verify.'};
        });
}

async function getSuite(proof) {
    const {verificationMethod} = proof;
    if (!verificationMethod) {
        throw {code: 400, message: 'Invalid proof!'};
    }
    const did = extractDidFromVerificationMethod(verificationMethod);
    return getDidDocument(did).then(didDocument => {
        const key = getKeyForVerificationMethod(verificationMethod, didDocument);
        const importKey = new Ed25519KeyPair({...key});
        return new Ed25519Signature2018({
            verificationMethod: key.id,
            key: importKey,
        });
    });
}

async function verifyPresentation(verifiablePresentation, challenge) {
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

    //attempt to fetch did document for presentation
    const presentationSuite = await getSuite(proof);
    return vcjs.verify({
        presentation: verifiablePresentation,
        suite: [...credentialSuites, presentationSuite],
        documentLoader,
        challenge
    }).then(result => {
        let checks = ['proof'];
        if (revocationChecks.length) {
            if(revocationChecks.every(result => result.revocation)){
                checks = [...checks, 'revocation']
            }
            else {
                throw {code: 500, message: "One or more credentials in the presentation has been revoked"};
            }
        }
        if (result.verified) {
            return {
                checks,
                warnings: [],
                errors: [],
            };
        } else {
            if (result.error) {
                throw result.error;
            }
            throw {code: 500, message: 'Could not verify.'};
        }
    });
}

function getKeyForVerificationMethod(verificationMethod, didDocument) {
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
    throw {code: 400, message: 'Could not find verification method in DID document'};
}

const _getVerificationFunction = async (vc) => {
    if (vc.credentialStatus) {
        return new Promise(resolve => resolve(verifyCredentialWithRevocation));
    }
    const {proof} = vc;
    const suite = await getSuite(proof);
    return credential => vcjs.verifyCredential({credential, suite, documentLoader});
}

export {verifyCredential, verifyPresentation, getSuite};
