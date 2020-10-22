import {registrar, driver} from '../resources/config/registrarConfig.json';
import base58 from 'bs58';
import crypto from 'crypto';
import fetch from 'node-fetch';

function registerNewDid(username, publicKeyBase58) {
    const registerUrl = `${registrar.url}/${driver.factom.registerEndpoint}?driverId=${driver.factom.id}`;
    const extIds = [
        crypto.createHash('sha256').update(Buffer.from(username)).digest('hex'),
        crypto.createHash('sha256').update(base58.decode(publicKeyBase58)).digest('hex'),
    ];

    const body = {
        options: {
            publicKeyBase58,
            extIds,
        },
        didDocument: {},
        secret: {}
    };

    return fetch(registerUrl, {
        method: 'post',
        body: JSON.stringify(body),
    }).then(res => res.json());
}

export {registerNewDid};