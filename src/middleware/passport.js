import passport from 'passport';
import {BasicStrategy} from 'passport-http';
import authConfig from '../resources/authConfig.json';

passport.use(new BasicStrategy(
    (username, password, done) => {
        if(username === authConfig.issuerAuthentication.username && password === authConfig.issuerAuthentication.password){
            return done(null, true);
        }
        return done(null, false);
    }
));

export default passport;
