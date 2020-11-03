import mongoose, {Schema} from 'mongoose';
import bcrypt from 'bcrypt';
import {fieldEncryption} from 'mongoose-field-encryption';
import RevocationConfigSchema from "./schemas/RevocationConfig";
import {encryptionSecret} from '../resources/config/databaseConfig.json';

const SALT_WORK_FACTOR = 10;

const UserSchema = new Schema({
    username: {type: String, required: true, index: {unique: true}},
    password: {type: String, required: true},
    did: {type: String, required: false},
    idSec: {type: String, required: false},
    revocationConfigs: [RevocationConfigSchema],
});

UserSchema.plugin(fieldEncryption, {fields: ['idSec'], secret: encryptionSecret});

UserSchema.pre('save', function (next) {
    const user = this;
    if (!user.isModified('password')) {
        return next();
    }
    bcrypt.genSalt(SALT_WORK_FACTOR, (err, salt) => {
        if (err) {
            return next(err);
        }

        bcrypt.hash(user.password, salt, (err, hash) => {
            if (err) {
                return next(err);
            }
            user.password = hash;
            next();
        });
    });
});

UserSchema.methods.comparePassword = function (candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

export default mongoose.model('User', UserSchema);
