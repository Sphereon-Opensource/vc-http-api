import {Router} from 'express';

const {extractDidFromVerificationMethod} = require('../lib/didDocumentService');
const veresOneDid = require('../resources/veresOneDid');
const {verifyCredentialStructure} = require('../lib/credentialService');
const {proveFactomPresentation, composeFactomPresentation} = require('../lib/factomService');
const factomDid = require('../resources/factomDid');

export default ({ config, db }) => {
    let api = Router();

    api.post('/presentations', (req, res) => {
       const {presentation, options} = req.body;
       if(!presentation){
           res.status(400).send("invalid input!");
           return;
       }
       if(!options || extractDidFromVerificationMethod(options.verificationMethod) === factomDid.identity.did){
           return proveFactomPresentation(presentation)
               .then(pres => res.status(200).send(pres))
               .catch(err => res.status(500).send(err));
       }
       res.status(500).send("error");
    });

    api.post('/composePresentation', (req, res) => {
        const {verifiableCredential} = req.body;
        const {options} = req.body;

        try{
            verifyCredentialStructure(verifiableCredential);
        } catch (err){
            res.status(err.code).send(err.message);
            return;
        }

        if(!options || options.holder === factomDid.identity.did){
            try{
                const pres = composeFactomPresentation(verifiableCredential);
                res.status(200).send(pres);
            } catch(err){
                res.status(500).send(err);
            }
        }
    });
    return api;

}
