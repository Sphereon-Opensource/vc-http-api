import {Schema} from "mongoose";

export default new Schema({
    publishMethod: {
        type: String,
        enum: ['github', 'hosted'],
        default: 'hosted',
    },
    gitHubOptions: {
        type: {
            token: {type: String, required: true},
            owner:{type: String, required: true},
            repo: {type: String, required: true},
            branch: {type: String, required: false},
            path: {type: String, required: false},
        },
        required: false,
    },
    hostedOptions: {
      type: {credentialId: {type: String, required: true}},
      required: false,
    },
    url: {type: String, required: false},
});
