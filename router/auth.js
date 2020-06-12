const express = require('express')
const User = require('../models/user.js')
const generate = require('nanoid/generate')
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer')
const crypto = require('crypto');
const router = express.Router()

const statusCodes = require("../utils/status");
const log = require("../utils/log");
const validEmail = require("../utils/validEmail");
const { clientID, sendResult } = require("../middleware/middleware")

router.use(clientID());

const jwtPublic = fs.readFileSync(path.resolve(__dirname, '../jwt-key.pub'));
const jwtExpirySecondsRefresh = 1209600;
const jwtExpirySecondsAccess = 900;

const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD
    }
});

const sendMails = false; // Send login emails

router.all('/auth/refresh', async(req, res) => {
    try {
        const user = await User.refreshTokenValid(req.cookies.refresh_token, req.cid)
        log.info(user.name + " is authorized");
        const access_token = await user.generateAccessToken()
        res.cookie('access_token', access_token, { HttpOnly: true, maxAge: jwtExpirySecondsAccess * 1000, domain: ".betahuhn.de", secure: true })
        sendResult(res, {
            name: user.name,
            email: user.email,
            username: user.username,
            user_id: user.user_id,
            rights: user.rights
        }, statusCodes.OK);
    } catch (err) {
        if (err.code == 401) {
            log.warn("not authorized")
            sendResult(res, "not authorized", statusCodes.UNAUTHORIZED);
        } else if (err.code == 402) {
            log.warn("No token")
            sendResult(res, "not authorized", statusCodes.UNAUTHORIZED);
        } else if (err.code == 405) {
            log.warn("No user found")
            sendResult(res, "not authorized", statusCodes.UNAUTHORIZED);
        } else {
            log.fatal(err)
            sendResult(res, "error", statusCodes.SERVER_ERROR);
        }
    }
})

router.all('/auth/authorize', async(req, res) => {
    const access_token = req.cookies.access_token || req.body.access_token;
    try {
        const user = await User.isAuthorized(access_token);
        log.info(user.name + " is authorized");
        sendResult(res, {
            name: user.name,
            email: user.email,
            username: user.username,
            user_id: user.user_id,
            rights: user.rights
        }, statusCodes.OK);
    } catch (err) {
        if (err.code == 555) {
            log.warn("no access token")
            sendResult(res, "no access token", 301);
        } else if (err.code === 401 || err.code === 402 || err.code === 405) {
            log.warn("not authorized")
            sendResult(res, "not authorized", statusCodes.UNAUTHORIZED);
        } else {
            log.fatal(err)
            sendResult(res, "error", statusCodes.SERVER_ERROR);
        }
    }
})

router.get('/refresh', async(req, res) => {
    try {
        const user = await User.refreshTokenValid(req.cookies.refresh_token, req.cid);
        log.info(user.name + " is authorized");
        const access_token = await user.generateAccessToken();
        const refresh_token = await user.generateRefreshToken(req.cid, req.cookies.refresh_token, req.clientInfo);
        res.cookie('refresh_token', refresh_token, { HttpOnly: true, maxAge: jwtExpirySecondsRefresh * 1000, domain: ".betahuhn.de", secure: true })
        res.cookie('access_token', access_token, { HttpOnly: true, maxAge: jwtExpirySecondsAccess * 1000, domain: ".betahuhn.de", secure: true })
        if (!req.query.ref) {
            sendResult(res, {
                access_token: access_token,
                refresh_token: refresh_token
            }, statusCodes.OK);
        } else if (req.query.ref.includes('http')) {
            res.redirect(req.query.ref);
        } else {
            res.redirect('https://' + req.query.ref);
        }
    } catch (err) {
        if (err.code === 401 || err.code === 402 || err.code === 405) {
            log.warn("not authorized")
            res.redirect("https://auth.betahuhn.de/login?ref=" + req.query.ref)
        } else {
            log.fatal(err)
            res.redirect("https://auth.betahuhn.de/login?ref=" + req.query.ref)
        }
    }
})

router.get('/auth/verify/register', async(req, res) => {
    if (!req.query.token) {
        return sendResult(res, "missing token", 405);
    }
    try {
        const user = await User.verifyRegisterToken(req.query.token);
        log.info(user.email + " is verified");
        const refresh_token = await user.generateRefreshToken(req.cid, undefined, req.clientInfo);
        const access_token = await user.generateAccessToken();
        res.cookie('refresh_token', refresh_token, { HttpOnly: true, maxAge: jwtExpirySecondsRefresh * 1000, domain: ".betahuhn.de", secure: true });
        res.cookie('access_token', access_token, { HttpOnly: true, maxAge: jwtExpirySecondsAccess * 1000, domain: ".betahuhn.de", secure: true });
        res.redirect("https://auth.betahuhn.de");
    } catch (err) {
        if (err.code == 405) {
            log.warn("Token expired or invalid")
            sendResult(res, "token invalid or expired", 405);
        } else {
            log.fatal(err)
            sendResult(res, "error", statusCodes.SERVER_ERROR);
        }
    }

})

router.all('/auth', async(req, res) => {
    const token = req.cookies.token;
    try {
        const user = await User.isAuthorized(token, req.cookies.refresh_token);
        log.success(user.name + " is authorized");
        sendResult(res, {
            name: user.name,
            email: user.email,
            username: user.username,
            user_id: user.user_id,
            rights: user.rights
        }, statusCodes.OK);
    } catch (error) {
        if (error.code == 555) {
            try {
                const user = await User.refreshTokenValid(req.cookies.refresh_token, req.cid);
                log.success(user.name + " is authorized");
                const access_token = await user.generateAccessToken();
                res.cookie('access_token', access_token, { HttpOnly: true, maxAge: jwtExpirySecondsAccess * 1000, domain: ".betahuhn.de", secure: true })
                sendResult(res, {
                    name: user.name,
                    email: user.email,
                    username: user.username,
                    user_id: user.user_id,
                    rights: user.rights
                }, statusCodes.OK);
            } catch (err) {
                if (err.code === 401 || err.code === 402 || err.code === 405) {
                    log.warn("not authorized")
                    sendResult(res, "not authorized", statusCodes.UNAUTHORIZED);
                } else {
                    log.fatal(err)
                    sendResult(res, "error", statusCodes.SERVER_ERROR);
                }
            }
        } else if (error.code === 401 || error.code === 402 || error.code === 405) {
            log.warn("not authorized")
            sendResult(res, "not authorized", statusCodes.UNAUTHORIZED);
        } else {
            log.fatal(error)
            sendResult(res, "error", statusCodes.SERVER_ERROR);
        }
    }
})

router.post('/auth/register', async(req, res) => {
    const { email, password, name } = req.body;
    let ref = '/';
    if (req.body.ref) {
        ref += req.body.ref;
    }
    log.info("Name: " + name + " Email: " + email)
    if (email.length < 5 || name.length <= 2) {
        log.warn("Not every field filled out");
        sendResult(res, "not every field filled out", 408);
    } else if (/\s/.test(password)) {
        log.warn("Password has whitespace");
        sendResult(res, "password has whitespace", 404);
    } else if (password.length > 20) {
        log.warn("Password is too long");
        sendResult(res, "password too long", 405);
    } else if (password.length < 8) {
        log.warn("Password is too short");
        sendResult(res, "password too short", 406);
    } else if (password.match("^[-_!?a-zA-Z0-9]*$")) {
        if (validEmail(email) == false) {
            log.warn(email + " not valid");
            sendResult(res, "email not valid", 407);
        } else {
            const register_token = crypto.randomBytes(32).toString('hex');
            const query = {
                user_id: generate('1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', 7),
                email: email,
                name: name,
                password: password,
                username: email,
                rights: {
                    user: true
                },
                registeredAt: new Date(),
                register_token: register_token,
                valid: false
            }
            const user = new User(query);
            user.save(async function(err, doc) {
                if (err) {
                    if (err.code == 11000) {
                        log.warn("Email already in use");
                        sendResult(res, "email already in use", 407);
                    } else {
                        log.fatal(err);
                        sendResult(res, "error", statusCodes.SERVER_ERROR);
                    }
                } else {
                    const mailOptions = {
                        from: 'no-reply@mxis.ch',
                        replyTo: 'no-reply@mxis.ch',
                        to: email,
                        subject: 'Verify your Email - Betahuhn',
                        html: `<h1>Verify your email address</h1><p>Hello ${name},</p><p>You or someone who used your email recently created an account at <a href="https://auth.betahuhn.de${ref}">auth.betahuhn.de${ref}</a>. If you didn't do this you can ignore this email, if you did you have to verify that you own this email address by clicking the link below:</p> <h><a href="https://auth.betahuhn.de/auth/verify/register?token=${register_token}">Verify Email</a></h><br><p>See you around 👋</p>`
                    };
                    transporter.sendMail(mailOptions, function(err, info) {
                        if (err) {
                            log.fatal(err);
                        } else {
                            log.info("Welcome email sent to: " + email);
                        }
                    });
                    sendResult(res, "success", 200);
                }
            })
        }
    } else {
        log.warn(password + " is not valid");
        sendResult(res, "password is not valid", 401);
    }
})

router.post('/auth/login', async(req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    try {
        const { email, password } = req.body
        const user = await User.findByCredentials(email, password)
        if (!user) {
            return sendResult(res, "user does not exist", 405);
        }
        const lastLogin = user.lastLogin;
        user.statistics.lastLogin = new Date();
        user.statistics.numLogins = (user.statistics.numLogins > 0) ? user.statistics.numLogins + 1 : 1;
        await user.save();
        const { name, user_id, rights, username } = user;
        const mailOptions = {
            from: 'no-reply@mxis.ch',
            replyTo: 'no-reply@mxis.ch',
            to: email,
            subject: 'New login with your BetaHuhn Account',
            html: `<h1>New Login</h1><p>Hello ${name},</p><p>Somebody recently logged into your BetaHuhn Account from the ip ${ip}. If this was you, ignore this email. If not we recommend you <a href="https://auth.betahuhn.de">reset your password</a> imediately</p><br><p>See you around 👋</p>`
        };
        if (sendMails) {
            transporter.sendMail(mailOptions, function(err, info) {
                if (err) {
                    log.fatal(err)
                } else {
                    log.info("Login email sent to: " + email);
                }
            });
        }
        const refresh_token = await user.generateRefreshToken(req.cid, undefined, req.clientInfo)
        const access_token = await user.generateAccessToken()
        res.cookie('refresh_token', refresh_token, { HttpOnly: true, maxAge: jwtExpirySecondsRefresh * 1000, domain: ".betahuhn.de", secure: true })
        res.cookie('access_token', access_token, { HttpOnly: true, maxAge: jwtExpirySecondsAccess * 1000, domain: ".betahuhn.de", secure: true })
        sendResult(res, {
            name: name,
            email: email,
            username: username,
            user_id: user_id,
            rights: rights,
            lastLogin: lastLogin
        }, statusCodes.OK);
    } catch (err) {
        if (err.code == 408) {
            log.warn("Wrong password")
            sendResult(res, "wrong password", 408);
        } else if (err.code == 405) {
            log.warn("user doesn't exist");
            sendResult(res, "user doesn't exist", 405);
        } else {
            log.fatal(err)
            sendResult(res, "error", statusCodes.SERVER_ERROR);
        }
    }
})

router.get('/auth/reset-password', async(req, res) => {
    if (!req.query.token) {
        return sendResult(res, "missing token", 405);
    }
    try {
        const user = await User.findByToken(req.query.token);
        log.info(user.name + " is authorized to change password");
        sendResult(res, "success", statusCodes.OK);
    } catch (err) {
        if (err.code == 405) {
            log.warn("Token expired or invalid");
            sendResult(res, "token expired or invalid", 405);
        } else {
            log.fatal(err);
            sendResult(res, "error", statusCodes.SERVER_ERROR);
        }
    }
})

router.post('/auth/reset-password', async(req, res) => {
    if (!req.body.email) {
        return sendResult(res, "no email specified", 402);
    }
    try {
        const user = await User.findByEmail(req.body.email)
        const token = await user.generateResetToken()
        const link = "https://auth.betahuhn.de/reset-password/new?token=" + token
        const mailOptions = {
            from: 'no-reply@mxis.ch',
            replyTo: 'no-reply@mxis.ch',
            to: user.email,
            subject: 'Setze dein betahuhn.de Passwort zurück',
            html: `<h1>Passwort Reset Anfrage</h1><p>Hallo ${user.name},</p><p>Du bekommst diese Email weil du oder jemand anderes angefragt hat dein Passwort zurück zu setzen. Um nun ein neues Passwort zu erstellen musst du nur auf diesen Link klicken: </p><a href="${link}">Neues Passwort erstellen</a>`
        };
        transporter.sendMail(mailOptions, function(err, info) {
            if (err) {
                log.fatal(err);
            } else {
                log.success("Reset email sent to: " + user.email);
            }
        });
        sendResult(res, {
            email: user.email
        }, statusCodes.OK);
    } catch (err) {
        if (err.code == 405) {
            log.warn("No user with that email found");
            sendResult(res, "no user with that email found", 405);
        } else {
            log.fatal(err)
            sendResult(res, "error", statusCodes.SERVER_ERROR);
        }
    }
})

router.post('/auth/new-password', async(req, res) => {
    if (!req.body.token) {
        log.warn("no token specified")
        return sendResult(res, "no token specified", statusCodes.BAD_REQUEST);
    }
    try {
        const password = req.body.password;
        const user = await User.findByToken(req.body.token);
        log.info(user.name + " is authorized to change password");
        if (/\s/.test(password)) {
            log.warn("password contains whitespace");
            sendResult(res, "password contains whitespace", 424);
        } else if (password.length > 20) {
            log.warn("password is too long");
            sendResult(res, "password too long", 425);
        } else if (password.length < 8) {
            log.warn("password is too short");
            sendResult(res, "password too short", 426);
        } else if (password.match("^[-_!?a-zA-Z0-9]*$")) {
            user.password = password;
            user.reset_token.token = null;
            user.reset_token.valid = false;
            await user.save();
            log.success("password changed")
            sendResult(res, "success", statusCodes.OK);
        }
    } catch (err) {
        if (err.code == 405) {
            log.warn("Token expired or invalid");
            sendResult(res, "token expired or invalid", 405);
        } else {
            log.fatal(err);
            sendResult(res, "error", statusCodes.SERVER_ERROR);
        }
    }
})

router.get('/auth/logout', async(req, res) => {
    let ref;
    if (!req.query.ref) {
        ref = "/";
    } else if (req.query.ref.includes('http')) {
        ref = req.query.ref;
    } else {
        ref = 'https://' + req.query.ref;
    }
    const token = req.cookies.refresh_token;
    if (token) {
        try {
            const payload = jwt.verify(token, jwtPublic);
            const user = await User.findByUserID(payload.user_id);
            if (user) {
                const all = req.query.all || false;
                const removed = await user.logoutToken(token, all);
                if (!removed) {
                    log.warn("couldn't remove tokens from db");
                }
            }
        } catch (err) {
            if (err instanceof jwt.JsonWebTokenError) {
                log.warn("couldn't remove tokens from db");
            } else {
                log.fatal(err);
            }
        }
    }
    res.clearCookie('refresh_token', { path: '/' });
    res.clearCookie('refresh_token', { domain: ".betahuhn.de" });
    res.clearCookie('access_token', { path: '/' });
    res.clearCookie('access_token', { domain: ".betahuhn.de" });
    res.clearCookie('token', { path: '/' });
    res.clearCookie('token', { domain: ".betahuhn.de" });
    res.json({ status: 200, ref: ref });
})

module.exports = router