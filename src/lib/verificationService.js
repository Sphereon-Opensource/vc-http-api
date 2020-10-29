import {verifyCredentialWithRevocation} from "./revocation";

const {getDidDocument} = require('./didDocumentService');
const {extractDidFromVerificationMethod} = require('./didDocumentService');
const {Ed25519KeyPair, suites: {Ed25519Signature2018}} = require('jsonld-signatures');
const {documentLoader} = require('./customDocumentLoader');
const vc = require('vc-js');

function verifyCredential(verifiableCredential) {
    const {proof} = verifiableCredential;
    const {verificationMethod} = proof;
    const did = extractDidFromVerificationMethod(verificationMethod);
    //attempt to fetch did document
    return getDidDocument(did).then(didDocument => {
        const key = getKeyForVerificationMethod(verificationMethod, didDocument);
        const importKey = new Ed25519KeyPair({...key});
        const suite = new Ed25519Signature2018({
            verificationMethod: key.id,
            key: importKey,
        });
        if(!verifiableCredential.credentialStatus){
            return vc.verifyCredential({credential: verifiableCredential, suite, documentLoader});
        }
        return verifyCredentialWithRevocation(verifiableCredential);
    }).then(result => {
        if (result.verified) {
            let checks = ['proof'];
            if(result.revocation){
                checks = [...checks, 'revocation']
            }
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
    if (verifiableCredential && Array.isArray(verifiableCredential)) {
        credentialSuites = await Promise.all(verifiableCredential
            .filter(vc => !!vc.proof)
            .map(vc => getSuite(vc.proof)));
    }

    //attempt to fetch did document for presentation
    const presentationSuite = await getSuite(proof);
    return vc.verify({
        presentation: verifiablePresentation,
        suite: [...credentialSuites, presentationSuite],
        documentLoader,
        challenge
    }).then(result => {
        if (result.verified) {
            return {
                checks: ['proof'],
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

export {verifyCredential, verifyPresentation, getSuite};
