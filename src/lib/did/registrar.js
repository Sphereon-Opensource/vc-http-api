import {registrar, driver} from '../../resources/config/registrarConfig.json';
import base58 from 'bs58';
import crypto from 'crypto';
import fetch from 'node-fetch';

const Network = Object.freeze({
    TESTNET: 'testnet',
    MAINNET: 'mainnet'
});

const DidMethods = Object.freeze({
    FACTOM: 'factom',
})

const registerNewDid = (username, publicKeyBase58, network) => {
    const registerUrl = `${registrar.url}/${driver.factom.registerEndpoint}?driverId=${driver.factom.id}`;
    const extIds = [
        crypto.createHash('sha256').update(Buffer.from(username)).digest('hex'),
        crypto.createHash('sha256').update(base58.decode(publicKeyBase58)).digest('hex'),
    ];

    const body = {
        options: {
            publicKeyBase58,
            extIds,
            network,
        },
        didDocument: {},
        secret: {}
    };

    return fetch(registerUrl, {
        method: 'post',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(body),
    }).then(res => res.json());
};

export default {registerNewDid, Network, DidMethods};
