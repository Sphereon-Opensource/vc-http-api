import {Router} from 'express';
import {
    checkRevocationStatus,
    createRevocationCredential,
    getRevocationCredential,
    publishRevocationCredential,
    updateRevocationCredential,
    validateRevocationConfig
} from '../lib/revocation';
import {factom} from '../lib/issuer';
import {handleErrorResponse} from '../lib/util';
import ResourceNotFoundError from '../lib/error/ResourceNotFoundError';
import InvalidRequestError from '../lib/error/InvalidRequestError';

const _parseRevocationRequest = req => {
    const {user, body} = req;
    const {id: configId} = req.params;
    const {revoked, index} = body;
    const {revocationConfigs} = user;
    const revocationConfig = revocationConfigs.find(config => config.id === configId);
    if (!revocationConfig) {
        const message = `No revocation configuration found for id: ${req.params.id}`;
        throw new ResourceNotFoundError(message);
    }
    let revocationIndex;
    try {
        revocationIndex = parseInt(index);
    } catch (err) {
        const message = `Could not parse index to integer. Supplied index: ${index}. 
            Originating error: ${err.message}`;
        throw new InvalidRequestError(message);
    }
    return {revocationIndex, revocationConfig, revoked};
};

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
                revocationListVC = await factom.issueFactomCredential(revocationListCred, {did, idSec});
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
            const message = `Could not find revocation with id: ${configId} for authenticated user.`;
            return res.status(404).send({message});
        }
        return res.status(200).send(revocationConfig);
    });

    api.put('/:id/list/manage', (req, res) => {
        let updateRevocationRequest;
        try {
            updateRevocationRequest = _parseRevocationRequest(req, res);
        } catch (err) {
            return handleErrorResponse(res, err);
        }
        const {revocationConfig, revocationIndex, revoked} = updateRevocationRequest;
        if (!revoked && !revocationConfig.allowRevocationReversal) {
            const message = `Reversing a revocation is not allowed by configuration with id: ${revocationConfig.id}`;
            return res.status(400).send({message});
        }
        const {did, idSec} = req.user;
        return getRevocationCredential(revocationConfig)
            .then(revocationListVC => updateRevocationCredential(revocationListVC, revocationIndex, revoked))
            .then(newRevocationListCred => factom.issueFactomCredential(newRevocationListCred, {did, idSec}))
            .then(newRevocationListVC => publishRevocationCredential(newRevocationListVC, revocationConfig))
            .then(() => res.status(200).send())
            .catch(err => handleErrorResponse(res, err));
    });

    api.post('/:id/list', (req, res) => {
        let checkRevocationRequest;
        try {
            checkRevocationRequest = _parseRevocationRequest(req, res);
        } catch (err) {
            return handleErrorResponse(res, err);
        }
        const {revocationConfig, revocationIndex} = checkRevocationRequest;
        return getRevocationCredential(revocationConfig)
            .then(revocationListVC => checkRevocationStatus(revocationListVC, revocationIndex))
            .then(result => res.status(200).send({revoked: result, index: revocationIndex}))
            .catch(err => handleErrorResponse(res, err));
    });
    return api;
};
