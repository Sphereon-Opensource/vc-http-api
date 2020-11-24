import {Router} from 'express';
import {resolver} from '../lib/did';
import {verifyCredentialStructure} from '../lib/credential';
import {factom} from '../lib/issuer';
import factomDid from '../resources/did/factomDid.json';

export default ({ config }) => {
    let api = Router();

    api.post('/presentations', (req, res) => {
       const {presentation, options} = req.body;
       if(!presentation){
           res.status(400).send("invalid input!");
           return;
       }
       if(!options || resolver.extractDidFromVerificationMethod(options.verificationMethod) === factomDid.identity.did){
           return factom.proveFactomPresentation(presentation)
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
                const pres = factom.composeFactomPresentation(verifiableCredential);
                res.status(200).send(pres);
            } catch(err){
                res.status(500).send(err);
            }
        }
    });
    return api;

}
