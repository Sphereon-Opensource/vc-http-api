import {Router} from 'express';
import Credential from '../models/Credential';

export default ({config}) => {
    let api = Router();
    api.get('/:id/revocation-credential.jsonld', (req, res) => {
        const {id} = req.params;
        Credential.findOne({id}, (err, {credential}) => {
            if (err) {
                res.status(404).send({message: 'Credential not found'});
            }
            res.status(200).send(credential);
        });
    });
    return api;
};
