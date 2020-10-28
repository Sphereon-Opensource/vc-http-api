import {app as FactomIdentityLib} from 'factom-identity-lib';

const {Ed25519KeyPair, suites: {Ed25519Signature2018}} = require('jsonld-signatures');
const {identity} = require('../resources/did/factomDid.json');
const {sign} = require('tweetnacl/nacl-fast');
const base58 = require('bs58');
const factomDid = require('../resources/did/factomDid.json');
const vc = require('vc-js');
const {documentLoader} = require('./customDocumentLoader');
const {v4: uuidv4} = require('uuid');

function idSecToBase58(idSec) {
    const bytes = base58.decode(idSec);
    const pkBytes = bytes.slice(5, 37);
    return base58.encode(pkBytes);
}

function generateNewFactomKeypair() {
    const factomId = FactomIdentityLib.generateRandomIdentityKeyPair();
    const privateKeyBase58 = idSecToBase58(factomId.secret);
    const keyPair = sign.keyPair.fromSeed(base58.decode(privateKeyBase58));
    return {idSec: factomId.secret, idPub: factomId.public, publicKeyBase58: base58.encode(keyPair.publicKey)}
}

function getFactomSuite() {
    return getFactomSuiteFrom(identity.did, identity.key_pairs[0].private_key)
}

function getFactomSuiteFrom(did, idSec) {
    const privateKeyBase58 = idSecToBase58(idSec);
    const keyPair = sign.keyPair.fromSeed(base58.decode(privateKeyBase58));
    const key = {
        id: `${did}#key-0`,
        type: 'Ed25519VerificationKey2018',
        controller: identity.did,
        publicKeyBase58: base58.encode(keyPair.publicKey),
        privateKeyBase58: base58.encode(keyPair.secretKey),
    };
    const importKey = new Ed25519KeyPair({...key});
    return new Ed25519Signature2018({
        verificationMethod: key.id,
        key: importKey,
    });
}

function issueFactomCredential(credential, options) {
    //verify options
    if (options && (!options.did || !options.idSec)) {
        return new Promise((resolve, reject) => reject({
            message: "Incorrect DID options supplied."
        }));
    }

    // check requirements
    if (credential.credentialSubject == null || credential.type == null || !Array.isArray(credential.type)) {
        console.log('Failed. Missing requirements.');
        return new Promise(((resolve, reject) => reject({
            message: 'Failed. Credential type is missing or malformed.',
            code: 500
        })));
    }

    // Check issuance date
    if (!credential.issuanceDate) {
        const today = new Date();
        const date = today.getFullYear() + '-' + (today.getMonth() + 1) + '-' + today.getDate();
        const time = today.getHours() + ':' + today.getMinutes() + ':' + today.getSeconds();
        credential.issuanceDate = date + 'T' + time;
    }

    // set correct issuer
    credential.issuer = _getCorrectIssuer(credential, options);

    // Todo: Verify DID
    const suite = options ? getFactomSuiteFrom(options.did, options.idSec) : getFactomSuite();
    return vc.issue({credential, suite, documentLoader});

}

function proveFactomPresentation(presentation) {
    return vc.signPresentation({
        presentation,
        suite: getFactomSuite(),
        challenge: uuidv4(),
        documentLoader,
        domain: 'issuer.example.com'
    });
}

function composeFactomPresentation(verifiableCredential) {
    return vc.createPresentation({verifiableCredential, suite: getFactomSuite(), documentLoader, holder: identity.did});
}

function _getCorrectIssuer(credential, options) {
    if (options && options.did) {
        return options.did;
    }
    return factomDid.identity.did;
}

module.exports = {
    issueFactomCredential,
    proveFactomPresentation,
    composeFactomPresentation,
    generateNewFactomKeypair,
    getFactomSuiteFrom
};
