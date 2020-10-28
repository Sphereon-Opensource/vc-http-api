import {Router} from "express";
import {PublishMethod, publish, createRevocationCredential, publishRevocationCredential} from "../lib/revocation";
import InvalidRequestError from "../lib/error/InvalidRequestError";
import {issueFactomCredential} from "../lib/factomService";

export default ({config}) => {
    let api = Router();

    api.post('/config', async (req, res) => {
        const {publishMethod, gitHubOptions} = req.body;
        switch (publishMethod) {
            case PublishMethod.GITHUB: {
                try {
                    await publish.github.validateGitHubOptions(gitHubOptions);
                } catch (e) {
                    if (e instanceof InvalidRequestError) {
                        return res.status(400).send({message: e.message});
                    }
                }
                const user = req.user;
                user.revocationConfig = {
                    publishMethod,
                    gitHubOptions
                };
                return user.save()
                    .then(() => res.status(200).send());
            }
            default: {
                const message = `Invalid publishMethod. Expected one of ${Object.values(PublishMethod)} 
                but got: ${publishMethod}`;
                return res.status(404).send({message});
            }
        }

    });

    api.get('/config', (req, res) => {
        const user = req.user;
        if (!user.revocationConfig) {
            return res.status(404).send({message: "No revocation config found for authenticated user."});
        }
        return res.status(200).send(user.revocationConfig);
    });

    api.post('/init', async (req, res) => {
        const {revocationConfig, did, idSec} = req.user;
        const {listSize} = req.body;
        if (!listSize || typeof listSize !== "number") {
            const message = `Unexpected listSize value. ${listSize} is not of type number.`;
            return res.status(400).send({message});
        }
        if (!revocationConfig){
            const message = "No revocation config found for authenticated user";
            return res.status(404).send({message});
        }
        const rc = await createRevocationCredential(listSize, did);
        const rvc = await issueFactomCredential(rc, {did, idSec});
        return publishRevocationCredential(rvc, revocationConfig)
            .then(url => res.status(200).send({url}))
            .catch(err => {
                if (err instanceof InvalidRequestError){
                    res.status(400).send({message: err.message});
                }
                res.status(500).send({message: err.message});
            });

    });

    return api;
};
