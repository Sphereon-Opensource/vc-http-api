import {Router} from "express";
import {PublishMethod, publish} from "../lib/revocation";
import InvalidRequestError from "../lib/error/InvalidRequestError";

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
        if(!user.revocationConfig){
            return res.status(404).send({message: "No revocation config found for authenticated user."});
        }
        return res.status(200).send(user.revocationConfig);
    });

    return api;
};
