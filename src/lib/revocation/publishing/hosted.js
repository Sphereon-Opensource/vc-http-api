import Promise from 'promise';
import Credential from '../../../models/Credential';
import {baseUrl} from '../../../config.json';
import ResourceConflictError from "../../error/ResourceConflictError";
import InvalidRevocationOptions from "../../error/InvalidRevocationOptions";

const publish = ({credentialId, content}) => {
    return new Promise((resolve, reject) => {
        Credential.findOne({id: credentialId}, (err, doc) => {
            if(err){
                reject(err);
            }
            if(!doc){
                doc = new Credential({id: credentialId});
            }
            doc.credential = content;
            doc.save()
                .then(() => resolve(_getHostedUrl(credentialId)));
        });
    })
};

const validateHostedOptions = ({credentialId}) => {
    return new Promise((resolve, reject) => {
        if(!credentialId){
            reject(new InvalidRevocationOptions("No credentialId specified for hosted options."));
        }
        Credential.findOne({id: credentialId}, (err, doc) => {
            if(doc){
                reject(new ResourceConflictError(`Credential with id ${credentialId} already exists.`));
            }
            resolve();
        })
    });
};

const _getHostedUrl = credentialId => {
    return `${baseUrl}/services/credentials/${credentialId}/revocation-credential.jsonld`;
};

export default {publish, validateHostedOptions};
