const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const crypto = require('crypto');
const fs = require('fs')
const log = require("../utils/log");

const jwtKey = fs.readFileSync('./jwt-key', 'utf8');
const jwtPublic = fs.readFileSync('./jwt-key.pub', 'utf8');
const jwtExpirySecondsRefresh = 1209600;
const jwtExpirySecondsAccess = 900;

const userSchema = mongoose.Schema({
    user_id: {
        type: String,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        validate: value => {
            if (!validator.isEmail(value)) {
                throw new Error({ error: 'Not a valid email address' })
            }
        }
    },
    username: {
        type: String,
        required: false,
        unique: true,
        lowercase: true,
        maxLength: 16,
        minLength: 5
    },
    password: {
        type: String,
        required: true,
        minLength: 8,
        maxLength: 64
    },
    tokens: [{
        token: {
            type: String,
            required: true
        },
        family: {
            type: String,
            required: true
        },
        created_at: Date,
        cid: String
    }],
    rights: {
        admin: Boolean,
        extended: Boolean,
        moderator: Boolean,
        user: Boolean
    },
    registeredAt: {
        type: Date,
        required: true
    },
    statistics: {
        lastLogin: Date,
        lastTokenRefresh: Date,
        numLogins: Number,
        clientData: [{
            cid: String,
            userAgent: String,
            language: String,
            lastSeen: Date
        }]
    },
    reset_token: {
        token: {
            type: String
        },
        valid: {
            type: Boolean
        },
        created_at: Date
    },
    register_token: {
        type: String
    },
    valid: {
        type: Boolean
    },
    resetPasswordExpires: {
        type: Date
    }
})

userSchema.pre('save', async function(next) {
    const user = this
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8)
    }
    next()
})

userSchema.methods.generateRefreshToken = async function(cid, oldRefreshToken, clientData) {
    /* CID is the client ID generated. It is based on specific request headers to make sure the client the token was created for is the one trying to generate a new token */
    log.info("Generating refresh token");
    const user = this;
    let token_family;
    if (oldRefreshToken != undefined) {
        for (i in user.tokens) {
            if (user.tokens[i].token == oldRefreshToken) {
                user.tokens[i].remove(oldRefreshToken);
                await user.save()
            }
        }
        try {
            token_family = await User.getTokenFamily(oldRefreshToken)
        } catch (error) {
            log.fatal(error)
            token_family = crypto.randomBytes(64).toString('hex');
        }
    } else {
        token_family = crypto.randomBytes(64).toString('hex');
    }

    const { user_id, name, rights, email } = user;
    const token = jwt.sign({ user_id, name, rights, email, token_family: token_family, cid: cid }, jwtKey, {
        issuer: "auth.betahuhn.de",
        subject: email,
        audience: user_id,
        algorithm: 'RS256',
        expiresIn: jwtExpirySecondsRefresh
    })

    user.tokens.push({ token: token, family: token_family, created_at: new Date(), cid: cid })
    user.statistics.lastTokenRefresh = new Date();

    if (user.statistics.clientData.length == 0) {
        user.statistics.clientData.push({ cid: cid, userAgent: clientData.userAgent, language: clientData.language, lastSeen: new Date() })
    } else {
        let found = false;
        for (i in user.statistics.clientData) {
            if (user.statistics.clientData[i].cid == cid) {
                found = true;
                user.statistics.clientData[i].lastSeen = new Date();
            }
        }
        if (!found) {
            user.statistics.clientData.push({ cid: cid, userAgent: clientData.userAgent, language: clientData.language, lastSeen: new Date() })
        }
    }
    await user.save()
    return token
}

userSchema.methods.generateAccessToken = async function() {
    const user = this;
    log.info("Generating access token")
    const { user_id, name, rights, email } = user;
    const token = jwt.sign({ user_id, name, rights, email }, jwtKey, {
        issuer: "auth.betahuhn.de",
        subject: user_id,
        algorithm: 'RS256',
        expiresIn: jwtExpirySecondsAccess
    })
    return token
}

userSchema.statics.isAuthorized = async function(token) {
    if (!token) {
        log.warn("No Access token")
        throw ({ error: 'generate new access token', code: 555 })
    }
    try {
        const payload = jwt.verify(token, jwtPublic) //Check if access token is still valid
        const user = await User.findOne({ user_id: payload.user_id })
        if (!user) {
            log.warn("No user found")
            throw ({ error: 'No user found', code: 405 })
        }
        return user
    } catch (err) {
        if (err instanceof jwt.TokenExpiredError) { //If access token expired check if refresh token valid
            log.warn("Access token expired")
            throw ({ error: 'generate new access token', code: 555 })
        } else if (err instanceof jwt.JsonWebTokenError) { //Access token not valid -> has to log in again
            log.warn("Access token not valid")
            throw ({ error: 'Unauthorized', code: 401 })
        }
        log.fatal(err)
        throw ({ error: err, code: 400 })
    }
}

userSchema.statics.refreshTokenValid = async function(token, clientID) {
    if (!token) {
        log.warn("No refresh token")
        throw ({ error: 'No token', code: 402 })
    }
    try {
        const payload = jwt.verify(token, jwtPublic);
        const { user_id, token_family } = payload;
        const user = await User.findOne({ user_id })
        if (!user) {
            throw ({ error: 'No user found', code: 405 })
        }
        /* Check if token on whitelist and cid match */
        const isValid = await user.isValidToken(token);
        if (!isValid || payload.cid != clientID) {
            log.warn("token not valid")
            const tokenLength = user.tokens.length;
            for (let i = 0; i < tokenLength; i++) {
                if (user.tokens[i].family == token_family) {
                    user.tokens.pop(user.tokens[i])
                }
            }
            await user.save()
            throw ({ error: 'Token not valid', code: 400 })
        }
        return user
    } catch (err) {
        if (err instanceof jwt.JsonWebTokenError) {
            throw ({ error: 'Unauthorized', code: 401 })
        }
        throw ({ error: err, code: 400 })
    }
}

userSchema.statics.getTokenFamily = async function(refresh_token) {
    try {
        const payload = jwt.verify(refresh_token, jwtPublic);
        return payload.token_family;
    } catch (err) {
        if (err instanceof jwt.JsonWebTokenError) {
            throw ({ error: 'Unauthorized', code: 401 })
        }
        throw ({ error: err, code: 400 })
    }
}

userSchema.methods.generateResetToken = async function() {
    const user = this;
    const token = crypto.randomBytes(64).toString('hex');
    user.reset_token = {
        token: token,
        valid: true,
        created_at: new Date()
    }
    const date = Date.now() + 3600000 * 3;
    user.resetPasswordExpires = date;
    await user.save();
    return token;
}

userSchema.methods.logoutToken = async function(token, all) {
    const user = this;
    let found = false;
    for (let i in user.tokens) {
        if (all) {
            user.tokens[i].remove();
            found = true;
        } else if (user.tokens[i].token == token) {
            user.tokens[i].remove(token);
            found = true;
        } else {
            found = false;
        }
    }
    await user.save()
    return found;
}

userSchema.methods.isValidToken = async function(token) {
    const user = this;
    for (let i in user.tokens) {
        if (user.tokens[i].token === token) {
            return true;
        }
    }
    log.warn("token not on whitelist")
    return false;
}

userSchema.statics.verifyRegisterToken = async(token) => {
    const user = await User.findOne({ register_token: token })
    if (!user) {
        throw ({ error: 'Token invalid or expired', code: 405 })
    }
    user.valid = true;
    await user.save();
    return user;
}

userSchema.statics.findByCredentials = async(email, password) => {
    const user = await User.findOne({ email })
    if (!user) {
        throw ({ error: 'User not found', code: 405 })
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
        throw ({ error: 'Wrong password', code: 408 });
    }
    return user;
}

userSchema.statics.findByUserID = async(user_id) => {
    const user = await User.findOne({ user_id });
    if (!user) {
        throw ({ error: 'No spot found', code: 405 });
    }
    return user;
}

userSchema.statics.findByEmail = async(email) => {
    const user = await User.findOne({ email });
    if (!user) {
        throw ({ error: 'No user found', code: 405 });
    }
    return user;
}

userSchema.statics.findByToken = async(token) => {
    const date = Date.now() + 3600000 * 2;
    const user = await User.findOne({ "reset_token.token": token, "reset_token.valid": true, resetPasswordExpires: { $gt: date } })
    if (!user) {
        throw ({ error: 'Token invalid or expired', code: 405 });
    }
    return user;
}

const User = mongoose.model('User', userSchema)

module.exports = User