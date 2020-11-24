import passport from 'passport';
import {Router} from 'express';
import {registrar} from '../lib/did';
import User from '../models/User';
import {factom} from '../lib/issuer';

export default ({config}) => {
    let api = Router();
    // login
    api.post('/login', passport.authenticate('basic', {session: false}),
        (req, res) => {
            res.send({
                token: req.user,
            });
        });

    // register new user and did
    if (!config.registrationActive) {
        return api;
    }

    api.post('/register', async (req, res) => {
        const {username, password, didOptions} = req.body;
        const network = didOptions && didOptions.network ? didOptions.network : registrar.Network.TESTNET;
        if (network !== registrar.Network.TESTNET && network !== registrar.Network.MAINNET) {
            const message =
                `Invalid network specified. Expected ${registrar.Network.MAINNET} or ${registrar.Network.TESTNET},
                 but got: ${network}`;
            return res.status(400).send({message});
        }

        if (didOptions.didMethod && !Object.values(registrar.DidMethods).includes(didOptions.didMethod)) {
            const message = `Unsupported DID method provided. Received : ${didOptions.didMethod},
                 Expected one of: ${Object.values(registrar.DidMethods)}`;
            return res.status(400).send({message});
        }

        if (!username || !password) {
            return res.status(400).send({message: 'username and password needed to register'})
        }
        if (await User.exists({username})) {
            return res.status(400).send({message: 'A user with that username already exists'});
        }
        // TODO: Add support for multiple DID methods. Currently there is no logic here supporting multiple DID methods.
        // The validation above will work for any extension of registrar.DidMethods, but the line below assumes did:factom
        // is the only option.
        const {publicKeyBase58, idSec} = factom.generateNewFactomKeypair();
        return registrar.registerNewDid(username, publicKeyBase58, network)
            .then(({didState}) => {
                const user = new User({
                    username,
                    password,
                    did: didState.identifier,
                    idSec,
                });
                return user.save()
                    .then(() => res.status(200).send({
                        did: didState.identifier,
                        username,
                    })).catch(() =>
                        res.status(500).send({message: 'Could not create new user'})
                    );
            }).catch(() =>
                res.status(500).send({message: 'Could not register a new DID'})
            );
    });

    return api;
}
