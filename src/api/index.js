import {Router} from 'express';
import passport from 'passport';
import issuer from './issuer';
import verifier from './verifier';
import holder from './holder';
import revocation from "./revocation";
import auth from './auth';
import apiInfo from '../resources/apiInfo';
import credentials from "./credentials";


export default ({config}) => {
    let api = Router();

    // mount the issuer resource
    api.use('/issue', passport.authenticate('bearer', {session: false}), issuer({config}));

    // mount the verifier resource
    api.use('/verify', verifier({config}));

    // mount the holder resource
    api.use('/prove', holder({config}));

    // mount the revocation resource
    api.use('/revocations', passport.authenticate('bearer', {session: false}), revocation({config}));

    // mount the mongo credential resource
    api.use('/credentials', credentials({config}));

    // mount authentication resource
    api.use('/auth', auth({config}));

    // perhaps expose some API metadata at the root
    api.get('/', (req, res) => {
        res.status(200).send(apiInfo);
    });

    return api;
}
