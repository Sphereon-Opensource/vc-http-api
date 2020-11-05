import {Router} from "express";
import {
    checkRevocationStatus,
    createRevocationCredential,
    getRevocationCredential,
    publishRevocationCredential,
    updateRevocationCredential,
    validateRevocationConfig
} from "../lib/revocation";
import {issueFactomCredential} from "../lib/factomService";
import {handleErrorResponse} from "../lib/util";

export default ({config}) => {
    let api = Router();

    api.post('', async (req, res) => {
            const revocationConfig = req.body;
            const user = req.user;
            try {
                await validateRevocationConfig(revocationConfig);
            } catch (err) {
                return handleErrorResponse(res, err);
            }
            const {id: configId} = revocationConfig;
            if (user.revocationConfigs.some(config => config.id === configId)) {
                const message = `Revocation configuration already exists with id: ${configId}`;
                return res.status(403).send({message});
            }
            const {listSize} = revocationConfig;
            const {did, idSec} = user;
            let revocationListCred, revocationListVC;
            try {
                revocationListCred = await createRevocationCredential(listSize, did);
                revocationListVC = await issueFactomCredential(revocationListCred, {did, idSec});
                revocationConfig.url = await publishRevocationCredential(revocationListVC, revocationConfig);
            } catch (err) {
                return handleErrorResponse(res, err);
            }
            user.revocationConfigs.push(revocationConfig);
            try {
                await user.save()
            } catch (err) {
                const message = `Could not save revocation config to authenticated user. 
                    Originating message: ${err.message}`;
                return res.status(500).send({message});
            }
            res.status(200).send(revocationConfig);
        }
    );

    api.get('', (req, res) => {
        const user = req.user;
        return res.status(200).send({revocations: user.revocationConfigs});
    });

    api.get('/:id', (req, res) => {
        const user = req.user;
        const {id: configId} = req.params;
        const revocationConfig = user.revocationConfigs.find(config => config.id === configId);
        if (!revocationConfig) {
            const message = `Could not find revocation for authenticated user with id: ${configId}`;
            return res.status(404).send({message});
        }
        return res.status(200).send(revocationConfig);
    });

    api.post('/:id/list/:index', (req, res) => {
        const {user, body} = req;
        const {index, id: configId} = req.params;
        const {revoked} = body;
        const {revocationConfigs, did, idSec} = user;
        const revocationConfig = revocationConfigs.find(config => config.id === configId);
        if (!revocationConfig) {
            const message = `No revocation configuration found for id: ${req.params.id}`;
            return res.status(404).send({message});
        }
        if (!revocationConfig.url) {
            const message = "Revocation credential not initialized.";
            return res.status(400).send({message})
        }
        let revocationIndex;
        try {
            revocationIndex = parseInt(index);
        } catch (err) {
            const message = `Could not parse index to integer. Supplied index: ${index}. 
            Originating error: ${err.message}`;
            return res.status(400).send({message});
        }
        return getRevocationCredential(revocationConfig)
            .then(revocationListVC => updateRevocationCredential(revocationListVC, revocationIndex, revoked))
            .then(newRevocationListCred => issueFactomCredential(newRevocationListCred, {did, idSec}))
            .then(newRevocationListVC => publishRevocationCredential(newRevocationListVC, revocationConfig))
            .then(() => res.status(200).send())
            .catch(err => handleErrorResponse(res, err));
    });

    api.get('/:id/list/:index', (req, res) => {
        const {index, id: configId} = req.params;
        const {user} = req;
        const revocationConfig = user.revocationConfigs.find(config => config.id === configId);
        if (!revocationConfig) {
            const message = `No revocation configuration found for id: ${req.params.id}`;
            return res.status(404).send({message});
        }
        if (!revocationConfig.url) {
            const message = "Revocation credential does not have a deployment URL.";
            res.status(500).send({message})
        }
        let revocationIndex;
        try {
            revocationIndex = parseInt(index);
        } catch (err) {
            const message = `Could not parse index to integer. Supplied index: ${index}. 
            Originating error: ${err.message}`;
            return res.status(400).send({message});
        }
        return getRevocationCredential(revocationConfig)
            .then(revocationListVC => checkRevocationStatus(revocationListVC, revocationIndex))
            .then(result => res.status(200).send({revoked: result}))
            .catch(err => handleErrorResponse(res, err));
    });
    return api;
};
