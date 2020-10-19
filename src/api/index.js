import {Router} from 'express';
import issuer from './issuer';
import verifier from './verifier';
import holder from './holder';
import apiInfo from '../resources/apiInfo';


export default ({config}) => {
    let api = Router();

    // mount the issuer resource
    api.use('/issue', issuer({config}));

    // mount the verifier resource
    api.use('/verify', verifier({config}));

    // mount the holder resource
    api.use('/prove', holder({config}));

    // perhaps expose some API metadata at the root
    api.get('/', (req, res) => {
        res.status(200).send(apiInfo);
    });

    return api;
}
