const express = require('express')
const User = require('../models/user.js')
const bodyParser = require('body-parser')
const bcrypt = require('bcryptjs');
const generate = require('nanoid/generate')
const request = require('request');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken')
const md5 = require('md5');
const cookieParser = require('cookie-parser')
const nodemailer = require('nodemailer')
var crypto = require('crypto');
var geoip = require('geoip-lite');

const router = express.Router()
const middleware = require("../middleware/middleware")
router.use(middleware.log())
router.use(middleware.clientID())

const saltRounds = 10;
const jwtKey = require('../key.json').jwtKey;
const jwtPublic = fs.readFileSync('./jwt-key.pub', 'utf8');
const jwtExpirySecondsRefresh = 1209600;
const jwtExpirySecondsAccess = 900; //900
const jwtExpirySecondsEmail = 900;

const api_key = require('../key.json').api_key;

const OutlookKey = require('../key.json').password;
let transporter = nodemailer.createTransport({
    service: 'Outlook365',
    auth: {
        user: 'mail@creerow.de',
        pass: OutlookKey
    }
});

var sendMails = false;

router.post('/auth/register', async(req, res) => {
    var email = req.body.email
    var password = req.body.password;
    var name = req.body.name;
    console.log("Name: " + name + " Email: " + email + " Password: " + password)
    if (email.length < 5 || name.length <= 2) {
        console.log("Not every field filled out");
        res.json({
            status: '408'
        });
    } else if (/\s/.test(password)) {
        console.log(password + " has whitespace");
        res.json({
            status: '404'
        });
    } else if (password.length > 20) {
        console.log(password + " is too long");
        res.json({
            status: '405'
        });
    } else if (password.length < 8) {
        console.log(password + " is too short");
        res.json({
            status: '406'
        });
    } else if (password.match("^[-_!?a-zA-Z0-9]*$")) {
        if (validEmail(email) == false) {
            console.log(email + " not valid");
            res.json({
                status: '407'
            });
        } else {
            var query = {
                user_id: generate('1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', 7),
                email: email,
                name: name,
                password: password,
                username: email,
                rights: {
                    user: true
                },
                registeredAt: CurrentDate()
            }
            try {
                let user = new User(query)
                user.save(async function(err, doc) {
                    if (err) {
                        console.log(err)
                        if (err.code == 11000) {
                            console.log("Email already in use")
                            res.json({
                                status: '407',
                                response: "Email already in use"
                            });
                        } else {
                            console.error(err)
                            res.json({
                                status: '400'
                            });
                        }
                    } else {
                        console.log(doc)
                        var name = doc.name
                        var email = doc.email
                        console.log(email)
                        const mailOptions = {
                            from: 'noreply@betahuhn.de',
                            replyTo: 'noreply@betahuhn.de',
                            to: email,
                            subject: 'Willkommen bei auth!',
                            html: `<h1>Herzlichen Glückwunsch!</h1><p>Hallo ${name},</p><p>Du hast soeben einen Account bei <a href="https://auth.betahuhn.de">auth.betahuhn.de</a> erstellt. <a href="https://auth.betahuhn.de">auth.betahuhn.de</a> ist im Moment noch in der Testphase, es kann sich also noch so einiges ändern. Schau also einfach immer mal wieder auf <a href="https://gotkite.betahuhn.de">auth.betahuhn.de</a> vorbei um keine neuen features zu verpassen!</p><p>Wir freuen uns auf dich 👋</p>`
                        };
                        if (sendMails) {
                            transporter.sendMail(mailOptions, function(err, info) {
                                if (err) {
                                    console.log(err)
                                } else {
                                    console.log(info.messageTime);
                                    console.log("Welcome email sent to: " + email)
                                }
                            });
                        }
                        var refresh_token = await user.generateRefreshToken(req.cid, undefined)
                        var access_token = await user.generateAccessToken()
                        res.cookie('refresh_token', refresh_token, { HttpOnly: true, maxAge: jwtExpirySecondsRefresh * 1000, domain: ".betahuhn.de", secure: true })
                        res.cookie('access_token', access_token, { HttpOnly: true, maxAge: jwtExpirySecondsAccess * 1000, domain: ".betahuhn.de", secure: true })
                        res.json({
                            status: '200'
                        });
                    }
                })
            } catch (error) {
                console.log(error)
                res.json({
                    status: '400'
                });
            }
        }
    } else {
        console.log(password + " is not valid");
        res.json({
            status: '401'
        });
    }
})

router.post('/auth/login', async(req, res) => {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    try {
        console.log(req.body.email)
        const { email, password } = req.body
        const user = await User.findByCredentials(email, password)
        if (!user) {
            return res.json({
                status: '405',
                response: "User does not exist"
            });
        }
        var name = user.name
        var user_id = user.user_id
        var rights = user.rights
        var username = user.username
        const mailOptions = {
            from: 'noreply@betahuhn.de',
            replyTo: 'noreply@betahuhn.de',
            to: email,
            subject: 'Neue Anmeldung bei deinem auth.betahuhn.de Account',
            html: `<h1>Neue Anmeldung</h1><p>Hallo ${name},</p><p>Es hat sich soeben jemand mit der IP: ${ip} bei deinem Konto angemeldet. Falls das du warst, kannst du diese Email ignorieren. Falls nicht, empfehlen wir dir dein Passwort schnellst möglich <a href="https://auth.betahuhn.de">zurück zu setzen</a> um deinen Account zu schützen.</p><p>Dein <a href="https://auth.betahuhn.de">auth.betahuhn.de</a> Team 👋</p>`
        };
        if (sendMails) {
            transporter.sendMail(mailOptions, function(err, info) {
                if (err)
                    console.log(err)
                else
                    console.log("Login email sent to: " + email)
            });
        }
        var refresh_token = await user.generateRefreshToken(req.cid, undefined)
        var access_token = await user.generateAccessToken()
        res.cookie('refresh_token', refresh_token, { HttpOnly: true, maxAge: jwtExpirySecondsRefresh * 1000, domain: ".betahuhn.de", secure: true })
        res.cookie('access_token', access_token, { HttpOnly: true, maxAge: jwtExpirySecondsAccess * 1000, domain: ".betahuhn.de", secure: true })
        res.json({
            status: 200,
            name: name,
            email: email,
            username: username,
            user_id: user_id,
            rights: rights,
            access_token: access_token,
            refresh_token: refresh_token
        })
    } catch (error) {
        if (error.code == 408) {
            console.log("Wrong password")
            res.json({
                status: '408',
                response: "Wrong password"
            });
        } else if (error.code == 405) {
            console.log(error.error)
            res.json({
                status: '405',
                response: "User doesn't exist"
            });

        } else {
            console.log(error)
            res.json({
                status: '400',
                response: "Error"
            });
        }
    }
})

router.all('/auth/refresh', async(req, res) => {
    try {
        const user = await User.refreshTokenValid(req.cookies.refresh_token, req.cid)
        console.log(user.name + " is authorized")
        var access_token = await user.generateAccessToken()
        res.cookie('access_token', access_token, { HttpOnly: true, maxAge: jwtExpirySecondsAccess * 1000, domain: ".betahuhn.de", secure: true })
        res.json({
            status: '200',
            response: 'success',
            name: user.name,
            email: user.email,
            username: user.username,
            user_id: user.user_id,
            rights: user.rights
        });
    } catch (error) {
        if (error.code == 401) {
            console.log("not authorized")
            res.json({
                status: '401',
                response: 'not authorized'
            });
        } else if (error.code == 402) {
            console.log("No token")
            res.json({
                status: '402',
                response: 'not authorized'
            });
        } else if (error.code == 405) {
            console.log("No user found")
            res.json({
                status: '405',
                response: 'not authorized'
            });
        } else {
            console.log(error)
            res.json({
                status: '401',
                response: 'not authorized'
            });
        }
    }
})

router.all('/auth/authorize', async(req, res) => {
    if (req.cookies.access_token == undefined) {
        req.cookies.access_token = req.body.access_token
    }
    try {
        const user = await User.isAuthorized(req.cookies.access_token)
        console.log(user.name + " is authorized")
        res.json({
            status: '200',
            response: 'success',
            name: user.name,
            email: user.email,
            username: user.username,
            user_id: user.user_id,
            rights: user.rights
        });
    } catch (error) {
        if (error.code == 555) {
            res.json({
                status: '301',
                response: 'no access token'
            });

        } else if (error.code == 401) {
            res.json({
                status: '401',
                response: 'not authorized'
            });
        } else if (error.code == 402) {
            res.json({
                status: '402',
                response: 'not authorized'
            });
        } else if (error.code == 405) {
            res.json({
                status: '405',
                response: 'not authorized'
            });
        } else {
            console.log(error)
            res.json({
                status: '401',
                response: 'not authorized'
            });
        }
    }
})

router.get('/refresh', async(req, res) => {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    console.log("ref: " + req.query.ref)
    console.log("UID: " + req.cid.slice(0,10))
    try {
        const user = await User.refreshTokenValid(req.cookies.refresh_token, req.cid)
        console.log(user.name + " is authorized")
        var access_token = await user.generateAccessToken()
        var refresh_token = await user.generateRefreshToken(req.cid, req.cookies.refresh_token)
        res.cookie('refresh_token', refresh_token, { HttpOnly: true, maxAge: jwtExpirySecondsRefresh * 1000, domain: ".betahuhn.de", secure: true })
        res.cookie('access_token', access_token, { HttpOnly: true, maxAge: jwtExpirySecondsAccess * 1000, domain: ".betahuhn.de", secure: true })
        if (!req.query.ref) {
            res.json({ status: 200, access_token: access_token, refresh_token: refresh_token })
        } else {
            if (req.query.ref.includes('http')) {
                res.redirect(req.query.ref)
            } else {
                res.redirect('https://' + req.query.ref)
            }
        }
    } catch (error) {
        console.log(error)
        if (!req.query.ref) {
            res.json({ status: error.code, response: error.error })
        } else {
            res.redirect("https://auth.betahuhn.de/login?ref=" + req.query.ref)
        }
    }
})

router.get('/cid', async(req, res) => {
    console.log(req.cid)
    res.json({ status: 200, cid: req.cid, data: req.clientInfo })
})

router.all('/auth', async(req, res) => {
    var token = req.cookies.token
    try {
        const user = await User.isAuthorized(token, req.cookies.refresh_token)
        console.log(user.name + " is authorized")
        res.json({
            status: '200',
            response: 'success',
            name: user.name,
            email: user.email,
            username: user.username,
            user_id: user.user_id,
            rights: user.rights
        });
    } catch (error) {
        if (error.code == 555) {
            try {
                const user = await User.refreshTokenValid(req.cookies.refresh_token)
                console.log(user.name + " is authorized")
                var access_token = await user.generateAccessToken()
                res.cookie('access_token', access_token, { HttpOnly: true, maxAge: jwtExpirySecondsAccess * 1000, domain: ".betahuhn.de", secure: true })
                res.json({
                    status: '200',
                    response: 'success',
                    name: user.name,
                    email: user.email,
                    username: user.username,
                    user_id: user.user_id,
                    rights: user.rights
                });
            } catch (error) {
                if (error.code == 401) {
                    res.json({
                        status: '401',
                        response: 'not authorized'
                    });
                } else if (error.code == 402) {
                    res.json({
                        status: '402',
                        response: 'not authorized'
                    });
                } else if (error.code == 405) {
                    res.json({
                        status: '405',
                        response: 'not authorized'
                    });
                } else {
                    console.log(error)
                    res.json({
                        status: '401',
                        response: 'not authorized'
                    });
                }
            }
        } else if (error.code == 401) {
            res.json({
                status: '401',
                response: 'not authorized'
            });
        } else if (error.code == 402) {
            res.json({
                status: '402',
                response: 'not authorized'
            });
        } else if (error.code == 405) {
            res.json({
                status: '405',
                response: 'not authorized'
            });
        } else {
            console.log(error)
            res.json({
                status: '401',
                response: 'not authorized'
            });
        }
    }
})

router.post('/api/user', async(req, res) => {
        var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        if (req.body.api_key == api_key && ip == "207.154.255.132") {
            try {
                const user = await User.findByUserID(req.body.user_id)
                res.json({
                    status: '200',
                    response: 'success',
                    name: user.name,
                    email: user.email,
                    username: user.username,
                    user_id: user.user_id,
                    rights: user.rights
                });
            } catch (err) {
                if (err.code == 405) {
                    console.log("No user with that id found")
                    return res.json({
                        status: '405',
                        response: "No user with that id found"
                    });
                } else {
                    console.log(err)
                    res.json({
                        status: '400',
                        response: "Error"
                    });
                }
            }
        } else {
            res.json({
                status: 401,
                response: "unauthorized"
            })
        }
    })
    /*
    request.post({ url: 'https://auth.betahuhn.de/api/user', form: { api_key: api_key, user_id: user_id } }, function(error, response2, body) {
                    const response = JSON.parse(String(response2.body));
                    if (response.status == 401) {
                        console.log("Error: Can't get user data")
                        return res.redirect('https://auth.betahuhn.de/login?ref=share.betahuhn.de')
                    } else if (response.status == 400) {
                        console.log("Error while getting user data")
                        return res.redirect('https://auth.betahuhn.de/login?ref=share.betahuhn.de')
                    } else if (response.status == 405) {
                        console.log("User not found")
                        return res.redirect('https://auth.betahuhn.de/login?ref=share.betahuhn.de')
                    } else if (response.status == 200) {
                        console.log(response.name + " is authorized")
                        res.json({
                            status: '200',
                            response: 'authenticated',
                            name: response.name,
                            user_id: response.user_id
                        });
                    }
                });*/

router.get('/auth/reset-password', async(req, res) => {
    if (!req.query.token) {
        return res.json({
            status: '405',
            response: "missing token"
        });
    }
    try {
        const user = await User.findByToken(req.query.token)
        console.log(user.name)
        res.json({
            status: 200
        })
    } catch (err) {
        if (err.code == 405) {
            console.log("Token expired or invalid")
            return res.json({
                status: '405',
                response: "token invalid or expired"
            });
        } else {
            console.log(err)
            res.json({
                status: '400',
                response: "Error"
            });
        }
    }
})

router.post('/auth/reset-password', async(req, res) => {
    if (!req.body.email) {
        return res.json({
            status: '402',
            response: "No email specified"
        });
    }
    console.log(req.body.email)
    try {
        const user = await User.findByEmail(req.body.email)
        var token = await user.generateResetToken()
        var link = "https://auth.betahuhn.de/auth/reset-password?token=" + token
        const mailOptions = {
            from: 'noreply@betahuhn.de',
            replyTo: 'noreply@betahuhn.de',
            to: user.email,
            subject: 'Setze dein betahuhn.de Passwort zurück',
            html: `<h1>Passwort Reset Anfrage</h1><p>Hallo ${user.name},</p><p>Du bekommst diese Email weil du oder jemand anderes angefragt hat dein Passwort zurück zu setzen. Um nun ein neues Passwort zu erstellen musst du nur auf diesen Link klicken: </p><a href="${link}"><button>Neues Passwort erstellen</button></a>`
        };
        if (sendMails) {
            transporter.sendMail(mailOptions, function(err, info) {
                if (err) {
                    console.log(err)
                    console.log(info)
                } else {
                    console.log(info);
                    console.log("Reset email sent to: " + user.email)
                }
            });
        }
        res.json({
            status: '200',
            email: user.email
        });
    } catch (err) {
        if (err.code == 405) {
            console.log("No user with that email found")
            return res.json({
                status: '405',
                response: "No user with that email found"
            });
        } else {
            console.log(err)
            res.json({
                status: '400',
                response: "Error"
            });
        }
    }
})

router.get('/auth/logout', async(req, res) => {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    if (!req.query.ref) {
        var ref = "/"
    } else {
        if (req.query.ref.indexOf('http') !== -1) {
            var ref = req.query.ref
        } else {
            var ref = 'https://' + req.query.ref;
        }
    }
    const token = req.cookies.refresh_token
        //console.log(req.cookies)
    if (!token) {
        console.log("No token")
        res.clearCookie('refresh_token', { path: '/' })
        res.clearCookie('refresh_token', { domain: ".betahuhn.de" })
        res.clearCookie('access_token', { path: '/' })
        res.clearCookie('access_token', { domain: ".betahuhn.de" })
        return res.json({ status: 200, ref: ref });
    } else {
        try {
            payload = jwt.verify(token, jwtPublic);
            //console.log(payload)
            const user = await User.findByUserID(payload.user_id)
            if (!user) {
                res.clearCookie('refresh_token', { path: '/' })
                res.clearCookie('refresh_token', { domain: ".betahuhn.de" })
                res.clearCookie('access_token', { path: '/' })
                res.clearCookie('access_token', { domain: ".betahuhn.de" })
                return res.json({ status: 200, ref: ref });
            }
            if (!req.query.all) {
                var all = false;
            } else {
                var all = req.query.all;
            }
            const removed = await user.logoutToken(token, all)
            if (removed) {
                res.clearCookie('refresh_token', { path: '/' })
                res.clearCookie('refresh_token', { domain: ".betahuhn.de" })
                res.clearCookie('access_token', { path: '/' })
                res.clearCookie('access_token', { domain: ".betahuhn.de" })
                console.log("Token cleared")
                return res.json({ status: 200, ref: ref });
            } else {
                console.log("Error, couldn't clear token from user db")
                res.clearCookie('refresh_token', { path: '/' })
                res.clearCookie('access_token', { path: '/' })
                return res.json({ status: 400, ref: ref });
            }
        } catch (e) {
            if (e instanceof jwt.JsonWebTokenError) {
                console.log("1 Unauthorized: " + e)
                return res.json({ status: 400, ref: ref });
            }
            console.log("Error: " + e)
            return res.json({ status: 400, ref: ref });
        }
    }
})

function CurrentDate() {
    let date_ob = new Date();
    let date = ("0" + date_ob.getDate()).slice(-2);
    let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
    let year = date_ob.getFullYear();
    let hours = date_ob.getHours();
    let minutes = date_ob.getMinutes();
    let seconds = date_ob.getSeconds();
    var current_date = year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds;
    return current_date;
}

function validEmail(email) {
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
}

module.exports = router