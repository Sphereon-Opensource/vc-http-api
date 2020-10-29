import mongoose, {Schema} from 'mongoose';

const CredentialSchema = new Schema({
    "@context": {type: Array, required: true},
    issuer: {type: String, required: true},
    issuanceDate: {type: String, required: true},
    type: {type: Array, required: true},
    credentialSubject: {type: Object, required: true},
    proof: {type: Object, required: false}
});


export default mongoose.model('Credential',
    new Schema({
        id: {type: String, required: true, index: {unique: true}},
        credential: CredentialSchema,
    }));
