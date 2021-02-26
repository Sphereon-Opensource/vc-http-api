import Secp256k1KeyPair from 'secp256k1-key-pair';
import {Ed25519KeyPair, RSAKeyPair} from 'crypto-ld';
import {suites} from 'jsonld-signatures';
import {resolver} from '../did';
import base58 from 'bs58';
import InvalidRequestError from '../error/InvalidRequestError';
import {VERIFICATION_METHOD_KEY_EXPANDED} from '../credential';

const KEY_TYPES = Object.freeze({
    EDDSA: 'Ed25519VerificationKey',
    ECDSA: 'ECDSASecp256k1VerificationKey',
    RSA: 'RSAVerificationKey'
});

const getSuite = async proof => {
    const verificationMethod = _getVerificationMethod(proof);
    const did = resolver.extractDidFromVerificationMethod(verificationMethod);
    return resolver.getDidDocument(did).then(didDocument => {
        const key = getKeyForVerificationMethod(verificationMethod, didDocument);
        return _getSuiteFromKey(key);

    });
};

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

const _getSuiteFromKey = key => {
    if (Array.isArray(key.type)) {
        if (key.type.includes(KEY_TYPES.RSA)) {
            return _getRsaSuite(key);
        } else if (key.type.includes(KEY_TYPES.ECDSA)) {
            return _getECDSASuite(key);
        }
    }
    // By default we return Ed25519 suites
    return _getEd25519Suite(key);

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
};

const _getECDSASuite = key => {
    const keyPairOptions = {
        ...key,
        type: 'EcdsaSecp256k1VerificationKey2019',
    };
    const keyPair = new Secp256k1KeyPair(keyPairOptions);
    return new suites.JwsLinkedDataSignature({
        type: 'EcdsaSecp256k1Signature2019',
        alg: 'ECDSA',
        LDKeyClass: Secp256k1KeyPair,
        verificationMethod: keyPair.id,
        key: keyPair
    });
};

const _publicKeyBase58ToPem = publcKeyBase58 => {
    const base64PublicKey = Buffer.from(base58.decode(publcKeyBase58)).toString('base64');
    return '-----BEGIN PUBLIC KEY-----\r\n' + base64PublicKey + '\r\n-----END PUBLIC KEY-----\r\n';
};

const _getVerificationMethod = proof => {
    let verificationMethod = proof.verificationMethod || proof[VERIFICATION_METHOD_KEY_EXPANDED];
    if (typeof verificationMethod === 'object') {
        verificationMethod = verificationMethod.id;
    }
    if (!verificationMethod) {
        throw new InvalidRequestError('Invalid proof!');
    }
    return verificationMethod
};

export {getSuite};
