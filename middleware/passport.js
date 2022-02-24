const passport = require('passport');
const {Strategy}= require('passport-local');
const {User} = require('../models');
const md5 = require('md5');

async function authenticate(username, password, done) {
    //get from db
    const user = await User.findOne( {
        where: {
            email: username
    }
    });
    //if no user or wrong password, error message
    if (!user || md5(password) !== user.password) {
        return done(null, false, {message: 'Incorrect email or password'})
    }
    //good
    return done(null, {
        id: user.id,
        username: user.email,
        displayName: user.first_name

    })
}
const validationStrategy = new Strategy({
        usernameField: 'email',
        passwordField: 'password'
    },
    authenticate);

passport.use(validationStrategy)

passport.serializeUser(function (user,cb) {
    process.nextTick(function () {
        cb(null, {id: user.id, username: user.email, displayName: user.displayName})
    });
});

passport.deserializeUser(async function (user, cb) {
    //const dbUser = await User.findByPk(user.id);
    process.nextTick(function () {
        return cb(null, user)
    });
});

module.exports.passport = passport;