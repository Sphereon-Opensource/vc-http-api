import {Router} from "express";
import {PublishMethod, publishing, createRevocationCredential, publishRevocationCredential} from "../lib/revocation";
import InvalidRequestError from "../lib/error/InvalidRequestError";
import {issueFactomCredential} from "../lib/factomService";

export default ({config}) => {
    let api = Router();

    api.post('/config', async (req, res) => {
            const {publishMethod, gitHubOptions, hostedOptions} = req.body;
            const user = req.user;
            try {
                switch (publishMethod) {
                    case PublishMethod.GITHUB:
                        await publishing.github.validateGitHubOptions(gitHubOptions);
                        break;
                    case PublishMethod.HOSTED:
                        await publishing.hosted.validateHostedOptions(hostedOptions);
                        break;
                    default:
                        const message = `Invalid publishMethod. Expected one of ${Object.values(PublishMethod)} 
                        but got: ${publishMethod}`;
                        throw new InvalidRequestError(message);
                }
            } catch (err) {
                if (err instanceof InvalidRequestError) {
                    return res.status(400).send({message: err.message});
                }
                return res.status(500).send({message: err.message});
            }

            user.revocationConfig = {
                publishMethod,
                gitHubOptions,
                hostedOptions
            };
            return user.save()
                .then(() => res.status(200).send());
        }
    );

    api.get('/config', (req, res) => {
        const user = req.user;
        if (!user.revocationConfig) {
            return res.status(404).send({message: "No revocation config found for authenticated user."});
        }
        return res.status(200).send(user.revocationConfig);
    });

    api.post('/init', async (req, res) => {
        const {user} = req;
        const {revocationConfig, did, idSec} = user;
        const {listSize} = req.body;
        if (!listSize || typeof listSize !== "number") {
            const message = `Unexpected listSize value. ${listSize} is not of type number.`;
            return res.status(400).send({message});
        }
        if (!revocationConfig) {
            const message = "No revocation config found for authenticated user";
            return res.status(404).send({message});
        }
        if (revocationConfig.url) {
            const message = "Revocation list already initialized, cannot reinitialize without overwriting statuses.";
            return res.status(403).send({message});
        }
        const rc = await createRevocationCredential(listSize, did);
        const rvc = await issueFactomCredential(rc, {did, idSec});
        return publishRevocationCredential(rvc, revocationConfig)
            .then(url => {
                user.revocationConfig.url = url;
                return user.save()
                    .then(() => res.status(200).send({url}));
            })
            .catch(err => {
                if (err instanceof InvalidRequestError) {
                    res.status(400).send({message: err.message});
                }
                res.status(500).send({message: err.message});
            });

    });

    return api;
};
