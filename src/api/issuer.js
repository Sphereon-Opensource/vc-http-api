import {Router} from 'express';
import {handleIssuanceError} from '../lib/util';

const util = require('util');
const {assertValidIssuanceCredential, getRequestedIssuer} = require('../lib/credentialService');
const factomDid = require('../resources/did/factomDid.json');
const {issueFactomCredential} = require('../lib/factomService');
const veresOneDid = require('../resources/did/veresOneDid.json');
const {issueVeresCredential} = require('../lib/veresOneService');

export default ({config}) => {
    let api = Router();

    // Internal Endpoints

    /*	Issue new credential
        Issues a credential and returns it in the response body.
        Support of this part of the API is REQUIRED for implementations.
    */
    api.post('/credentials', async (req, res) => {
        if (!req.body.credential) {
            res.status(400).send("No credential specified in request");
        }

        const credential = req.body.credential;
        const options = req.body.options;

        //check credential
        try {
            assertValidIssuanceCredential(credential);
        } catch (err) {
            handleIssuanceError(res, err);
            return;
        }

        //extract issuer from options
        let requestedIssuer;
        if (!options) {
            // if no options provided, use the account did
            requestedIssuer = req.user.did;
        } else {
            // else use the requested did
            requestedIssuer = await getRequestedIssuer(options)
                .catch(err => {
                    handleIssuanceError(res, err);
                    return false;
                });
        }

        if (!requestedIssuer) {
            return;
        }
        console.log(`Issuing on DID: ${requestedIssuer}`);
        switch (requestedIssuer) {
            case factomDid.identity.did:
                return issueFactomCredential(credential)
                    .then(result => res.status(201).send(result))
                    .catch(err => handleIssuanceError(res, err));
            case veresOneDid.did:
                return issueVeresCredential(credential)
                    .then(result => res.status(201).send(result))
                    .catch(err => handleIssuanceError(res, err, req));
            default:
                const {did, idSec} = req.user;
                if(!did || !idSec){
                    return res.status(400).send("No DID found for user");
                }
                return issueFactomCredential(credential, {did, idSec})
                    .then(result => res.status(201).send(result))
                    .catch(err => handleIssuanceError(res, err));
        }
    });

    /*	Compose and issue new credential
        Composes and issues a credential and returns it in the response body.
        Support of this part of the API is OPTIONAL for implementations.
    */
    api.post('/composeAndIssueCredential', (req, res) => {
        // not yet implemented

        res.status(501).send({message: "Not yet implemented."});
    });

    return api;
};
