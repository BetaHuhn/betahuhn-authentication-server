const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const crypto = require('crypto');
const fs = require('fs')

const jwtKey = fs.readFileSync('./jwt-key', 'utf8');
const jwtPublic = fs.readFileSync('./jwt-key.pub', 'utf8');
const jwtExpirySecondsRefresh = 1209600;
const jwtExpirySecondsAccess = 900; //900

const userSchema = mongoose.Schema({
    user_id: {
        type: String,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true,
        trim: true
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
    console.log("Generating refresh token");
    const user = this;
    if (oldRefreshToken != undefined) {
        for (i in user.tokens) {
            if (user.tokens[i].token == oldRefreshToken) {
                user.tokens[i].remove(oldRefreshToken);
                await user.save()
            }
        }
        try {
            var token_family = await User.getTokenFamily(oldRefreshToken)
            console.log("Using old family")
        } catch (error) {
            console.log(error)
            console.log("Generate new family")
            var token_family = crypto.randomBytes(64).toString('hex');
        }
    } else {
        console.log("Generate new family")
        var token_family = crypto.randomBytes(64).toString('hex');
    }
    var user_id = user.user_id
    var name = user.name
    var rights = user.rights
    var email = user.email
    const token = jwt.sign({ user_id, name, rights, email, token_family: token_family, cid: cid }, jwtKey, {
        issuer: "auth.betahuhn.de",
        subject: email,
        audience: user_id,
        algorithm: 'RS256',
        expiresIn: jwtExpirySecondsRefresh
    })
    user.tokens.push({ token: token, family: token_family, created_at: CurrentDate(), cid: cid })
    user.statistics.lastTokenRefresh = CurrentDate()
    if(user.statistics.clientData.length == 0){
        user.statistics.clientData.push({cid: cid, userAgent: clientData.userAgent, language: clientData.language, lastSeen: CurrentDate()})
    }else{
        var found = false;
        for(i in user.statistics.clientData){
            if(user.statistics.clientData[i].cid == cid){
                found = true;
                user.statistics.clientData[i].lastSeen = CurrentDate()
            }
        }
        if(!found){
            user.statistics.clientData.push({cid: cid, userAgent: clientData.userAgent, language: clientData.language, lastSeen: CurrentDate()})
            console.log("Adding new client device:")
            console.log({cid: cid, userAgent: clientData.userAgent, language: clientData.language, lastSeen: CurrentDate()})
        }
    }
    //console.log(user.statistics.clientData)
    await user.save()
    return token
}

userSchema.methods.generateAccessToken = async function() {
    const user = this
    console.log("Generating access token")
    var user_id = user.user_id
    var name = user.name
    var rights = user.rights
    var email = user.email
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
        console.log("No Access token")
        throw ({ error: 'generate new access token', code: 555 })
    }
    var payload
    try {
        payload = jwt.verify(token, jwtPublic) //Check if access token is still valid
        var user_id = payload.user_id
        const user = await User.findOne({ user_id })
        if (!user) {
            console.log("No user found")
            throw ({ error: 'No user found', code: 405 })
        }
        return user
    } catch (e) {
        if (e instanceof jwt.TokenExpiredError) { //If access token expired check if refresh token valid
            console.log("Access token expired")
            throw ({ error: 'generate new access token', code: 555 })
        } else if (e instanceof jwt.JsonWebTokenError) { //Access token not valid -> has to log in again
            console.log("Access token not valid")
            throw ({ error: 'Unauthorized', code: 401 })
        }
        console.log("Error: " + e)
        throw ({ error: e, code: 400 })
    }
}

userSchema.statics.refreshTokenValid = async function(token, clientID) {
    if (!token) {
        console.log("No refresh token")
        throw ({ error: 'No token', code: 402 })
    }
    var payload
    try {
        payload = jwt.verify(token, jwtPublic) //Check if refresh token is still valid
        var user_id = payload.user_id;
        var token_family = payload.token_family;
        console.log("Family: " + token_family.slice(0, 10))
        console.log("Saved cid: " + payload.cid)
        console.log("Send cid: " + clientID)
        var user = await User.findOne({ user_id })
        if (!user) {
            throw ({ error: 'No user found', code: 405 })
        }
        var isValid = await user.isValidToken(token) //Check if token is still on whitelist
        if (payload.cid != clientID) {
            console.log("Saved cid: " + payload.cid)
            console.log("Send cid: " + clientID)
            console.log("cid don't match")
            isValid = false;
        }
        if (!isValid) { //If token not on whitelist or client identification doesn't match saved cid
            //console.log(user.tokens)
            //console.log(user.tokens.length)
            var tokenLength = user.tokens.length;
            for (i = 0; i < tokenLength; i++) {
                //console.log(i)
                //console.log("Family: " + user.tokens[i].family)
                if (user.tokens[i].family == token_family) {
                    // console.log("match")
                    user.tokens.pop(user.tokens[i])
                }
            }
            //user.tokens.pop(user.tokens[0])
            console.log("removed")
                //console.log(user.tokens)
            await user.save()
            throw ({ error: 'Token not valid', code: 400 })
        }
        return user
    } catch (e) {
        if (e instanceof jwt.JsonWebTokenError) { //Refresh token not valid -> has to log in again
            throw ({ error: 'Unauthorized', code: 401 })
        }
        throw ({ error: e, code: 400 })
    }
}

userSchema.statics.getTokenFamily = async function(refresh_token) {
    try {
        payload = jwt.verify(refresh_token, jwtPublic) //Check if refresh token is still valid
        var user_id = payload.user_id;
        var token_family = payload.token_family;
        console.log("Family: " + token_family.slice(0, 10))
        return token_family
    } catch (e) {
        if (e instanceof jwt.JsonWebTokenError) { //Refresh token not valid -> has to log in again
            throw ({ error: 'Unauthorized', code: 401 })
        }
        throw ({ error: e, code: 400 })
    }
}

userSchema.methods.generateResetToken = async function() {
    const user = this
    var token = crypto.randomBytes(64).toString('hex');
    user.reset_token = {
        token: token,
        valid: true,
        created_at: CurrentDate()
    }
    var date = Date.now() + 3600000 * 3;
    console.log(date)
    user.resetPasswordExpires = date
    await user.save()
    return token
}

userSchema.methods.logoutToken = async function(token, all) {
    const user = this
        //console.log(user.tokens)
    for (i in user.tokens) {
        if (all) {
            user.tokens[i].remove();
            var found = true;
        } else if (user.tokens[i].token == token) {
            user.tokens[i].remove(token);
            var found = true;
        } else {
            var found = false;
        }
    }
    await user.save()
    return found;
}

userSchema.methods.isValidToken = async function(token) {
    const user = this
    console.log(user.tokens)
    console.log(token)
    for (i in user.tokens) {
        if (user.tokens[i].token == token) {
            return true
        }
    }
    console.log("token not on whitelist")
    return false
}

userSchema.statics.verifyRegisterToken = async(token) => {
    const user = await User.findOne({ register_token: token })
    if (!user) {
        throw ({ error: 'Token invalid or expired', code: 405 })
    }
    user.valid = true;
    await user.save()
    return user
}

userSchema.statics.findByCredentials = async(email, password, username) => {
    const user = await User.findOne({ email })
    if (!user) {
        throw ({ error: 'User not found', code: 405 })
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password)
    if (!isPasswordMatch) {
        throw ({ error: 'Wrong password', code: 408 })
    }
    return user
}

userSchema.statics.findByUserID = async(user_id) => {
    const user = await User.findOne({ user_id })
    if (!user) {
        throw ({ error: 'No spot found', code: 405 })
    }
    return user
}

userSchema.statics.findByEmail = async(email) => {
    const user = await User.findOne({ email })
    if (!user) {
        throw ({ error: 'No user found', code: 405 })
    }
    return user
}

userSchema.statics.findByToken = async(token) => {
    //console.log(token)
    var date = Date.now() + 3600000 * 2
        //console.log(date)
    const user = await User.findOne({ reset_token: { token: token, valid: true }, resetPasswordExpires: { $gt: Date.now() + 3600000 * 2 } })
    if (!user) {
        throw ({ error: 'Token invalid or expired', code: 405 })
    }
    return user
}

function CurrentDate() {
    let date_ob = new Date();
    let date = ("0" + date_ob.getDate()).slice(-2);
    let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
    let year = date_ob.getFullYear();
    let hours = date_ob.getHours() + 1;
    let minutes = date_ob.getMinutes();
    let seconds = date_ob.getSeconds();
    var current_date = year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds;
    return current_date;
}

const User = mongoose.model('User', userSchema)

module.exports = User