import {Schema} from "mongoose";

const RevocationConfigSchema = new Schema({
    id: {
        type: String,
        index: true,
        required: true,
    },
    publishMethod: {
        type: String,
        enum: ['github', 'mongo'],
        default: 'mongo',
    },
    gitHubOptions: {
        type: {
            token: {type: String, required: true},
            owner:{type: String, required: true},
            repo: {type: String, required: true},
            branch: {type: String, required: false},
            path: {type: String, required: false},
            useGitHubPages: {type: Boolean, required: false}
        },
        required: false,
    },
    mongoOptions: {
      type: {credentialId: {type: String, required: true}},
      required: false,
    },
    url: {type: String, required: false},
    listSize: {type: Number, required: true},
});

RevocationConfigSchema.methods.toJSON = function() {
    const obj = this.toObject();
    delete obj._id;
    return obj;
}

export default RevocationConfigSchema;
