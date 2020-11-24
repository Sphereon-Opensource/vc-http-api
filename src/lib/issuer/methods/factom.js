import {app as FactomIdentityLib} from 'factom-identity-lib';
import {sign} from 'tweetnacl/nacl-fast';
import base58 from 'bs58';
import {Ed25519KeyPair} from 'crypto-ld';
import {suites} from 'jsonld-signatures';
import vcjs from 'vc-js';
import {documentLoader} from '../../credential';
import {identity} from '../../../resources/did/factomDid.json';
import {v4 as uuidv4} from 'uuid';
import {parseVcJsIssuanceError} from '../../util';


const idSecToBase58 = (idSec) => {
    const bytes = base58.decode(idSec);
    const pkBytes = bytes.slice(5, 37);
    return base58.encode(pkBytes);
};

const generateNewFactomKeypair = () => {
    const factomId = FactomIdentityLib.generateRandomIdentityKeyPair();
    const privateKeyBase58 = idSecToBase58(factomId.secret);
    const keyPair = sign.keyPair.fromSeed(base58.decode(privateKeyBase58));
    return {idSec: factomId.secret, idPub: factomId.public, publicKeyBase58: base58.encode(keyPair.publicKey)};
};

const getFactomSuite = () => {
    return getFactomSuiteFrom(identity.did, identity.key_pairs[0].private_key);
};

const getFactomSuiteFrom = (did, idSec) => {
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
    return new suites.Ed25519Signature2018({
        verificationMethod: key.id,
        key: importKey,
    });
};

const issueFactomCredential = (credential, options) => {
    //verify options
    if (options && (!options.did || !options.idSec)) {
        return new Promise((resolve, reject) => reject({
            message: 'Incorrect DID options supplied.'
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

    // TODO: Verify DID
    const suite = options ? getFactomSuiteFrom(options.did, options.idSec) : getFactomSuite();
    return vcjs.issue({credential, suite, documentLoader})
        .catch(err => parseVcJsIssuanceError(err));
}

const proveFactomPresentation = (presentation) => {
    return vcjs.signPresentation({
        presentation,
        suite: getFactomSuite(),
        challenge: uuidv4(),
        documentLoader,
        domain: 'issuer.example.com'
    });
};

const composeFactomPresentation = (verifiableCredential) => {
    return vcjs.createPresentation({
        verifiableCredential,
        suite: getFactomSuite(),
        documentLoader,
        holder: identity.did
    });
};

const _getCorrectIssuer = (credential, options) => {
    if (options && options.did) {
        return options.did;
    }
    return identity.did;
};

export default {
    issueFactomCredential,
    proveFactomPresentation,
    composeFactomPresentation,
    generateNewFactomKeypair,
    getFactomSuiteFrom
};
