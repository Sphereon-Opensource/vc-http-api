import {Router} from 'express';
import {constructCredentialWithConfig, fillDefaultValues, validateIssuerConfig} from "../lib/issuer";
import {handleErrorResponse} from "../lib/util";
const {issueFactomCredential} = require("../lib/factomService");

export default ({config}) => {
    let api = Router();

    api.post('', async (req, res) => {
        const issuerConfig = req.body;
        const user = req.user;
        try {
            validateIssuerConfig(issuerConfig);
        } catch (err) {
            handleErrorResponse(res, err);
            return;
        }
        if (user.issuerConfigs.find(config => config.id === issuerConfig.id)) {
            const message = `Issuer config with id: ${issuerConfig.id} already exists for authenticated user`;
            res.status(403).send({message});
        }
        user.issuerConfigs.push(issuerConfig);
        try {
            await user.save()
        } catch (err) {
            const message = `Could not save revocation config to authenticated user. 
                    Originating message: ${err.message}`;
            return res.status(500).send({message});
        }
        res.status(200).send(fullIssuerConfig);
    });

    api.get('/:id', (req, res) => {
        const user = req.user;
        const {id: configId} = req.params;
        const issuerConfig = user.issuerConfigs.find(config => config.id === configId);
        if (!issuerConfig) {
            const message = `Could not find issuer config with id: ${configId} for authenticated user.`;
            return res.status(404).send({message});
        }
        return res.status(200).send(issuerConfig);
    });

    api.post('/:id/credentials', (req, res) => {
        const user = req.user;
        const {id: configId} = req.params;
        const {credentialSubject, revocationListIndex} = req.body;
        const issuerConfig = user.issuerConfigs.find(config => config.id === configId);
        if (!issuerConfig) {
            const message = `Could not find issuer config with id: ${configId} for authenticated user.`;
            return res.status(404).send({message});
        }
        const {did, idSec} = user;
        const credential = constructCredentialWithConfig({
            credentialSubject,
            revocationListIndex: revocationListIndex.toString(),
            did,
            config: issuerConfig
        });
        return issueFactomCredential(credential, {did, idSec})
            .then(result => res.status(201).send(result))
            .catch(err => handleIssuanceError(res, err));
    });
    return api;
}
