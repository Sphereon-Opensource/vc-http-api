import {Schema} from "mongoose";

const IssuerConfigSchema = new Schema({
    id: {
        type: String,
        index: true,
        required: true,
    },
    context: {
        type: [String],
        required: true,
    },
    type: {
        type: [String],
        required: true,
    },
    revocationListCredential: {
        type: String,
        required: false,
    }
});

IssuerConfigSchema.methods.toJSON = function() {
    const obj = this.toObject();
    delete obj._id;
    return obj;
}

export default IssuerConfigSchema;
