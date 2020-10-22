import passport from 'passport';
import {Router} from 'express';
import {registerNewDid} from "../lib/registrarService";
import User from '../models/User';
import factomService from '../lib/factomService';

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
    api.post('/register', async (req, res) => {
        const {username, password} = req.body;
        if (!username || !password) {
            return res.status(400).send({message: "username and password needed to register"})
        }
        if (await User.exists({username})) {
            return res.status(400).send({message: "A user with that username already exists"});
        }
        const {publicKeyBase58, idSec} = factomService.generateNewFactomKeypair();
        return registerNewDid(username, publicKeyBase58)
            .then(({didState}) => {
                const user = new User({
                    username,
                    password,
                    did: didState.identifier,
                    idSec,
                });
                return user.save()
                    .then(() => res.status(200).send())
                    .catch(() =>
                        res.status(500).send({message: 'Could not create new user'})
                    );
            }).catch(() =>
                res.status(500).send({message: "Could not register a new DID"})
            );
    });

    return api;
}