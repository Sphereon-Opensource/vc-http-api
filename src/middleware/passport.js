import passport from 'passport';
import {BasicStrategy} from 'passport-http';
import {Strategy as BearerStrategy} from 'passport-http-bearer';
import jwt from 'jwt-simple';
import authConfig from '../resources/config/authConfig.json';
import User from "../models/User";

passport.use(new BasicStrategy(
    (username, password, done) => {
        User.findOne({username}, function (err, user) {
            if (err || !user) {
                return done(err, false);
            }
            user.comparePassword(password, function (err, isMatch) {
                if (err || !isMatch) {
                    return done(err, false);
                }
                done(null, jwt.encode({username}, authConfig.jwtSecret));
            })
        });
    }
));

passport.use(new BearerStrategy((token, done) => {
    const {username} = jwt.decode(token, authConfig.jwtSecret);
    User.findOne({username}, (err, user) => {
        if (err) {
            return done(err);
        }
        if (!user) {
            return done(null, false);
        }
        return done(null, user, {scope: 'all'});
    });
}))

export default passport;
