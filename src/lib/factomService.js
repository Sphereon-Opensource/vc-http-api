const {Ed25519KeyPair, suites: {Ed25519Signature2018}} = require('jsonld-signatures');
const {identity} = require('../resources/factomDid');
const {sign} = require('tweetnacl/nacl-fast');
const base58 = require('bs58');
const factomDid = require('../resources/factomDid.json');
const vc = require('vc-js');
const {documentLoader} = require('./customDocumentLoader');
const {v4: uuidv4} = require('uuid');

function idSecToBase58(idSec) {
    const bytes = base58.decode(idSec);
    const pkBytes = bytes.slice(5, 37);
    return base58.encode(pkBytes);
}

function getFactomSuite() {
    const privateKeyBase58 = idSecToBase58(identity.key_pairs[0].private_key);
    const keyPair = sign.keyPair.fromSeed(base58.decode(privateKeyBase58));
    const key = {
        id: `${identity.did}#key-0`,
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

function issueFactomCredential(credential) {
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

    if (credential.issuer !== factomDid.identity.did) {
        credential.issuer = factomDid.identity.did;
    }
    // Todo: Verify DID
    return vc.issue({credential, suite: getFactomSuite(), documentLoader});
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

module.exports = {issueFactomCredential, proveFactomPresentation, composeFactomPresentation};
