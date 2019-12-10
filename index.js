const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser')
const bcrypt = require('bcryptjs');
const generate = require('nanoid/generate')
const request = require('request');
const fs = require('fs');
const path = require('path');
const app = express();
const jwt = require('jsonwebtoken')
const md5 = require('md5');
const cookieParser = require('cookie-parser')
const nodemailer = require('nodemailer')

const saltRounds = 10;
const jwtKey = require('./key.json').key;
const jwtExpirySeconds = 86400
const jwtExpirySecondsEmail = 900

var connection = mysql.createConnection({
    host: "localhost",
    user: "creerow",
    password: "***REMOVED***",
    database: "urlshortener"
});
connection.connect(function(err) {
    if (err) {
        return console.error('error: ' + err.message);
    }
    console.log('Connected to the MySQL server.');
});

const OutlookKey = require('./key.json').password;
let transporter = nodemailer.createTransport({
    service: 'Outlook365', // no need to set host or port etc.
    auth: {
        user: 'mail@creerow.de',
        pass: OutlookKey
    }
});

app.listen(2000, () => console.log('listening on port 2000'));
app.use(express.static('public'));
app.use(express.json({ limit: '1mb' }));
app.set("view engine", "ejs");
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }))
app.use(cookieParser())

app.post('/auth', (request, response) => {
    //var ip = request.headers['x-forwarded-for'] || request.connection.remoteAddress;
    const token = request.body.token
    if (!token) {
        console.log('Got a authentication request');
        console.log("No token")
        return response.json({
            status: '404',
            response: 'no token'
        });
    }
    const ip = request.body.ip
    const agent = md5(request.body.agent)
    console.log('Got a authentication request from: ' + ip);
    var payload
    try {
        payload = jwt.verify(token, jwtKey)
        console.log(payload.name + " is authorized")
        if (payload.ip == ip || payload.agent == agent) {
            response.json({
                status: '200',
                response: 'success',
                name: payload.name,
                email: payload.email,
                user_id: payload.user_id,
                is_admin: payload.is_admin
            });
        } else {
            console.log("Unauthorized because ip or agent don't match")
            return response.json({
                status: '401',
                response: 'unauthorized'
            });
        }
    } catch (e) {
        if (e instanceof jwt.JsonWebTokenError) {
            console.log("Unauthorized: " + e)
            return response.json({
                status: '401',
                response: 'unauthorized'
            });
        }
        console.log("Error: " + e)
        return response.json({
            status: '400',
            response: 'error'
        });
    }
});

app.post('/api/login', async(request, response) => {
    var ip = request.headers['x-forwarded-for'] || request.connection.remoteAddress;
    console.log('Got a login request from: ' + ip);
    const email = request.body.email;
    const passwd = request.body.passwd;
    console.log("Email: " + email + " password: " + passwd)
    getUID(email).then(function(result) {
        if (result != undefined) {
            var user_id = result.user_id
            var name = result.name
            var is_admin = result.admin
            var agent = md5(request.header('user-agent'))
            var referrer = request.header('referrer')
            console.log("User ID: " + user_id + " | Name: " + name + " | Is admin: " + is_admin)
            checkPasswd(passwd, user_id).then(function(result) {
                if (result) {
                    //console.log("Password: " + passwd + " is correct")
                    const token = jwt.sign({ user_id, name, is_admin, email, ip, agent }, jwtKey, {
                        issuer: "auth.betahuhn.de",
                        subject: email,
                        audience: user_id,
                        algorithm: 'HS256',
                        expiresIn: jwtExpirySeconds
                    })
                    console.log("Sent cookie")
                    response.cookie('token', token, { HttpOnly: true, maxAge: jwtExpirySeconds * 1000, domain: "betahuhn.de", secure: true })
                    parseIP(ip).then(function(result) {
                        var country = result.country_name
                        console.log(country)
                        const mailOptions = {
                            from: 'noreply@betahuhn.de', // sender address
                            replyTo: 'noreply@betahuhn.de',
                            to: email,
                            subject: 'Neue Anmeldung bei deinem betahuhn.de Account',
                            html: `<img src="https://auth.betahuhn.de/logo.png" alt="Betahuhn" width="200" height="200"><h1>Neue Anmeldung</h1><p>Hallo ${name},</p><p>Es hat sich soeben jemand aus ${country} (IP: ${ip}) bei deinem Konto angemeldet. Falls das du warst, kannst du diese Email ignorieren. Falls nicht, empfehlen wir dir dein Passwort schnellst möglich <a href="https://betahuhn.de">zurück zu setzen</a> um deinen Account zu schützen.</p><p>Dein <a href="https://betahuhn.de">betahuhn.de</a> Team 👋</p>`

                        };
                        transporter.sendMail(mailOptions, function(err, info) {
                            if (err)
                                console.log(err)
                            else
                                console.log(info);
                            console.log("Login email sent to: " + email)
                        });
                        response.json({
                            status: '200',
                            response: 'success'
                        });
                    })
                } else {
                    console.log("Password: " + passwd + " is incorrect")
                    response.json({
                        status: '400',
                        response: 'wrong password'
                    });
                }
            })
        } else {
            console.log("User does not exist: " + email)
            response.json({
                status: '401',
                response: 'user does not exist'
            });
        }
    })
});

app.post('/api/register', async(request, response) => {
    var ip = request.headers['x-forwarded-for'] || request.connection.remoteAddress;
    console.log('Got a request from: ' + ip);
    const email = mysql_real_escape_string(request.body.email);
    const name = mysql_real_escape_string(request.body.name);
    const passwd = mysql_real_escape_string(request.body.passwd);
    console.log("Name: " + name + " Email: " + email + " password: " + passwd)
    checkEmailExist(email).then(function(result) {
        if (result == false) {
            if (email.length < 5 || name.length <= 2) {
                console.log("Not every field filled out");
                response.json({
                    status: '408'
                });
            } else if (/\s/.test(passwd)) {
                console.log(passwd + " has whitespace");
                response.json({
                    status: '404'
                });
            } else if (passwd.length > 20) {
                console.log(passwd + " is too long");
                response.json({
                    status: '405'
                });
            } else if (passwd.length < 8) {
                console.log(passwd + " is too short");
                response.json({
                    status: '406'
                });
            } else if (passwd.match("^[-_!?a-zA-Z0-9]*$")) {
                if (validEmail(email) == false) {
                    console.log(email + " not valid");
                    response.json({
                        status: '400'
                    });
                } else {
                    console.log(passwd + " | and " + email + " | is valid");
                    user_id = generate('1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', 5)
                    bcrypt.hash(passwd, saltRounds, function(err, hash) {
                        var today = new Date();
                        var date = today.getFullYear() + '-' + (today.getMonth() + 1) + '-' + today.getDate();
                        var time = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
                        var dateTime = date + ' ' + time;
                        var sql = `INSERT INTO userbase (user_id, ip, created_at, email, name, passwd, admin) VALUES ('${user_id}', '${ip}', '${dateTime}', '${email}', '${name}', '${hash}', '0');`
                        connection.query(sql);
                        console.log("User: " + name + " | Email: " + email + " | User ID: " + user_id + " added to db")
                        getUID(email).then(function(result) {
                            if (result != undefined) {
                                var user_id = result.user_id
                                var name = result.name
                                var is_admin = result.admin
                                console.log("User ID: " + user_id + " | Name: " + name + " | Is admin: " + is_admin)
                                checkPasswd(passwd, user_id).then(function(result) {
                                    if (result) {
                                        //console.log("Password: " + passwd + " is correct")
                                        const token = jwt.sign({ user_id, name, is_admin, email }, jwtKey, {
                                            issuer: "auth.betahuhn.de",
                                            subject: email,
                                            audience: user_id,
                                            algorithm: 'HS256',
                                            expiresIn: jwtExpirySeconds
                                        })
                                        response.cookie('token', token, { maxAge: jwtExpirySeconds * 1000, domain: "betahuhn.de" })
                                        const mailOptions = {
                                            from: 'noreply@betahuhn.de', // sender address
                                            replyTo: 'noreply@betahuhn.de',
                                            to: email,
                                            subject: 'Willkommen bei BetaHuhn!',
                                            html: `<img src="https://auth.betahuhn.de/logo.png" alt="Betahuhn" width="200" height="200"><h1>Herzlichen Glückwunsch!</h1><p>Hallo ${name},</p><p>Du hast soeben einen Account bei <a href="https://betahuhn.de">betahuhn.de</a> erstellt. <a href="https://betahuhn.de">betahuhn.de</a> ist im Moment noch in der Testphase, es kann sich also noch so einiges ändern. Schau also einfach immer mal wieder auf <a href="https://betahuhn.de">betahuhn.de</a> vorbei um keine neuen features zu verpassen!</p><p>Wir freuen uns auf dich 👋</p>`

                                        };
                                        transporter.sendMail(mailOptions, function(err, info) {
                                            if (err)
                                                console.log(err)
                                            else
                                                console.log(info.messageTime);
                                            console.log("Welcome email sent to: " + email)
                                        });
                                        response.json({
                                            status: '200',
                                            response: 'success'
                                        });
                                    } else {
                                        console.log("Password: " + passwd + " is incorrect")
                                        response.json({
                                            status: '400',
                                            response: 'wrong password'
                                        });
                                    }
                                })
                            } else {
                                console.log("User does not exist: " + email)
                                response.json({
                                    status: '401',
                                    response: 'user does not exist'
                                });
                            }
                        })
                    });
                }
            } else {
                console.log(passwd + " is not valid");
                response.json({
                    status: '407'
                });
            }
        } else {
            console.log("Email already in use: " + email)
            response.json({
                status: '401'
            });
        }
    })

    response.status(200);

});

app.post('/api/reset-password/auth', (req, response) => {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    var agent = req.headers['user-agent']
    var email = req.body.email
    console.log('Got a /api/reset-password/auth request from: ' + ip);
    getUID(email).then(function(result) {
        if (result != undefined) {
            var user_id = result.user_id
            var name = result.name
            var is_admin = result.admin
            const token = jwt.sign({ email }, jwtKey, {
                issuer: "auth.betahuhn.de",
                subject: email,
                algorithm: 'HS256',
                expiresIn: jwtExpirySeconds
            })
            response.cookie('token', token, { maxAge: jwtExpirySeconds * 1000, domain: "betahuhn.de" })
            response.json({
                status: '200',
                response: 'success',
                email: email
            });
        } else {
            response.json({
                status: '400',
                response: "Email does not exist"
            });
        }
    })

})

app.get('/api/reset-password', (req, response) => {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    var agent = req.headers['user-agent']
    var link = req.query.link
    console.log('Got a GET /api/reset-password request from: ' + ip);
    if (link == undefined) {
        console.log("No link")
        response.json({
            status: '400',
            response: 'error'
        });

    } else {
        //console.log(link)
        getToken(link).then(function(result) {
            if (result != undefined) {
                var user_id = result.user_id
                var name = result.name
                var valid = result.valid
                var is_admin = result.is_admin
                var email = result.email
                if (valid == 1) {
                    try {
                        payload = jwt.verify(link, jwtKey)
                        console.log(payload.email + " is authorized to reset password")
                        const token = jwt.sign({ user_id, name, is_admin, email, ip, agent }, jwtKey, {
                            issuer: "auth.betahuhn.de",
                            subject: email,
                            audience: user_id,
                            algorithm: 'HS256',
                            expiresIn: jwtExpirySeconds
                        })
                        var sql = `UPDATE userbase SET reset_token = '${token}', valid = 1 WHERE email = '${email}';`
                        connection.query(sql);
                        response.cookie('token', token, { HttpOnly: true, maxAge: jwtExpirySeconds * 1000, domain: "betahuhn.de", secure: true })
                        return response.redirect("https://auth.betahuhn.de/new-password")
                    } catch (e) {
                        if (e instanceof jwt.JsonWebTokenError) {
                            console.log("Unauthorized: " + e)
                            return response.redirect("https://auth.betahuhn.de/reset-password/expired?reason=not-valid")
                        }
                        console.log("Error: " + e)
                        return response.redirect("https://auth.betahuhn.de/reset-password/expired")
                    }
                } else {
                    console.log("Token is expired - redirecting to /expired")
                    response.redirect("https://auth.betahuhn.de/reset-password/expired?reason=expired")
                }

            } else {
                console.log("Token is not valid - redirecting to /expired")
                response.redirect("https://auth.betahuhn.de/reset-password/expired?reason=not-valid")
            }
        })

    }


});

app.post('/api/reset-password', (req, response) => {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    var agent = req.headers['user-agent']
    var confirm = req.body.confirm
    console.log('Got a /api/reset-password request from: ' + ip);
    const token2 = req.cookies.token;
    if (!token2) {
        console.log("No token")
        response.json({
            status: '400',
            response: "unauthorized"
        });
    } else {
        try {
            payload = jwt.verify(token2, jwtKey)
            console.log(payload.email + " is authorized to reset password")
            var email = payload.email
            getUID(email).then(function(result) {
                if (result != undefined) {
                    var user_id = result.user_id
                    var name = result.name
                    var is_admin = result.admin
                    const token = jwt.sign({ email }, jwtKey, {
                        issuer: "auth.betahuhn.de",
                        subject: email,
                        algorithm: 'HS256',
                        expiresIn: jwtExpirySeconds
                    })
                    var sql = `UPDATE userbase SET reset_token = '${token}', valid = 1 WHERE email = '${email}';`
                    connection.query(sql);
                    var link = "https://auth.betahuhn.de/api/reset-password?link=" + token
                    if (confirm == true) {
                        const mailOptions = {
                            from: 'noreply@betahuhn.de', // sender address
                            replyTo: 'noreply@betahuhn.de',
                            to: email,
                            subject: 'Setze dein betahuhn.de Passwort zurück',
                            html: `<img src="https://auth.betahuhn.de/logo.png" alt="Betahuhn" width="200" height="200"><h1>Passwort Reset Anfrage</h1><p>Hallo ${name},</p><p>Du bekommst diese Email weil du oder jemand anderes angefragt hat dein Passwort zurück zu setzen. Um nun ein neues Passwort zu erstellen musst du nur auf diesen Link klicken: </p><a href="${link}"><button>Neues Passwort erstellen</button></a>`

                        };
                        transporter.sendMail(mailOptions, function(err, info) {
                            if (err)
                                console.log(err)
                            else
                                console.log(info.messageTime);
                            console.log("Reset email sent to: " + email)
                        });

                        response.json({
                            status: '200',
                            response: "success",
                            email: email
                        });
                    }
                } else {
                    console.log("Email not found")
                    return response.json({
                        status: '400',
                        response: 'error'
                    });
                }
            })
        } catch (e) {
            if (e instanceof jwt.JsonWebTokenError) {
                console.log("Unauthorized: " + e)
                return response.json({
                    status: '400',
                    response: 'unauthorized'
                });
            }
            console.log("Error: " + e)
            return response.json({
                status: '400',
                response: 'error'
            });
        }
    }
});

app.post('/api/new-password', (req, response) => {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    var agent = req.headers['user-agent']
    console.log('Got a POST /api/new-password request from: ' + ip);
    const token = req.cookies.token;
    if (!token) {
        console.log("No token")
        response.json({
            status: '400',
            response: "unauthorized"
        });
    } else {
        console.log("Got token")
        request.post({ url: 'https://auth.betahuhn.de/auth', form: { token: token, ip: ip, agent: agent } }, function(error, response2, body) {
            //console.log(response2.body)
            const res = JSON.parse(String(response2.body));
            if (res.status == 401) {
                console.log("Unauthorized")
                response.json({
                    status: '400',
                    response: "unauthorized"
                });
            } else if (res.status == 400) {
                response.json({
                    status: '400',
                    response: "unauthorized"
                });
            } else if (res.status == 404) {
                response.json({
                    status: '400',
                    response: "unauthorized"
                });
            } else if (res.status == 200) {
                getToken(token).then(function(result) {
                    if (result != undefined) {
                        var user_id = result.user_id
                        var name = result.name
                        var valid = result.valid
                        var email = result.email
                        if (valid == 1) {
                            console.log(res.name + " is authorized")
                            var passwd = req.body.passwd
                            var passwd2 = req.body.passwd2
                            if (passwd == passwd2) {
                                if (/\s/.test(passwd)) {
                                    console.log(passwd + " has whitespace");
                                    response.json({
                                        status: '404'
                                    });
                                } else if (passwd.length > 20) {
                                    console.log(passwd + " is too long");
                                    response.json({
                                        status: '405'
                                    });
                                } else if (passwd.length < 8) {
                                    console.log(passwd + " is too short");
                                    response.json({
                                        status: '406'
                                    });
                                } else if (passwd.match("^[a-zA-Z0-9!?]*$")) {
                                    bcrypt.hash(passwd, saltRounds, function(err, hash) {
                                        checkPasswd(hash, user_id).then(function(result) {
                                            if (result) {
                                                console.log("Password already in use")
                                                response.json({
                                                    status: '402',
                                                    response: "Same password as before"
                                                });
                                            } else {
                                                console.log("Password is valid")
                                                var sql = `UPDATE userbase SET passwd = '${hash}', valid = 0 WHERE user_id = '${user_id}';`
                                                connection.query(sql);
                                                console.log("Changed password successfully")
                                                const mailOptions = {
                                                    from: 'noreply@betahuhn.de', // sender address
                                                    replyTo: 'noreply@betahuhn.de',
                                                    to: email,
                                                    subject: 'Dein Passwort wurde geändert',
                                                    html: `<img src="https://auth.betahuhn.de/logo.png" alt="Betahuhn" width="200" height="200"><h1>Dein Passwort wurde geändert</h1><p>Hallo ${name},</p><p>Falls du das Passwort geändert hast kannst du diese Email ignorieren. Falls nicht, empfehlen wir dir dein Passwort schnellst möglich <a href="https://betahuhn.de">zurück zu setzen</a> um deinen Account zu schützen.</p><p>Dein <a href="https://betahuhn.de">betahuhn.de</a> Team 👋</p>`

                                                };
                                                transporter.sendMail(mailOptions, function(err, info) {
                                                    if (err)
                                                        console.log(err)
                                                    else
                                                        console.log(info.messageTime);
                                                    console.log("Reset email sent to: " + email)
                                                });
                                                response.json({
                                                    status: '200',
                                                    response: "authorized",
                                                    name: name,
                                                    email: email
                                                });
                                            }
                                        })

                                    })
                                }

                            } else {
                                response.json({
                                    status: '401',
                                    response: "passwords don't match"
                                });
                            }
                        } else {
                            response.json({
                                status: '400',
                                response: "unauthorized"
                            });
                        }
                    } else {
                        console.log(res.name + " is authorized")
                        var passwd = req.body.passwd
                        var passwd2 = req.body.passwd2
                        var name = res.name
                        var user_id = res.user_id
                        var email = res.email
                        if (passwd == passwd2) {
                            if (/\s/.test(passwd)) {
                                console.log(passwd + " has whitespace");
                                response.json({
                                    status: '404'
                                });
                            } else if (passwd.length > 20) {
                                console.log(passwd + " is too long");
                                response.json({
                                    status: '405'
                                });
                            } else if (passwd.length < 8) {
                                console.log(passwd + " is too short");
                                response.json({
                                    status: '406'
                                });
                            } else if (passwd.match("^[a-zA-Z0-9!?]*$")) {
                                bcrypt.hash(passwd, saltRounds, function(err, hash) {
                                    checkPasswd(hash, user_id).then(function(result) {
                                        if (result) {
                                            console.log("Password already in use")
                                            response.json({
                                                status: '402',
                                                response: "Same password as before"
                                            });
                                        } else {
                                            console.log("Password is valid")
                                            var sql = `UPDATE userbase SET passwd = '${hash}', valid = 0 WHERE user_id = '${user_id}';`
                                            connection.query(sql);
                                            console.log("Changed password successfully")
                                            const mailOptions = {
                                                from: 'noreply@betahuhn.de', // sender address
                                                replyTo: 'noreply@betahuhn.de',
                                                to: email,
                                                subject: 'Dein Passwort wurde geändert',
                                                html: `<img src="https://auth.betahuhn.de/logo.png" alt="Betahuhn" width="200" height="200"><h1>Dein Passwort wurde geändert</h1><p>Hallo ${name},</p><p>Falls du das Passwort geändert hast kannst du diese Email ignorieren. Falls nicht, empfehlen wir dir dein Passwort schnellst möglich <a href="https://betahuhn.de">zurück zu setzen</a> um deinen Account zu schützen.</p><p>Dein <a href="https://betahuhn.de">betahuhn.de</a> Team 👋</p>`

                                            };
                                            transporter.sendMail(mailOptions, function(err, info) {
                                                if (err)
                                                    console.log(err)
                                                else
                                                    console.log(info.messageTime);
                                                console.log("Welcome email sent to: " + email)
                                            });
                                            response.json({
                                                status: '200',
                                                response: "authorized",
                                                name: name,
                                                email: email
                                            });
                                        }
                                    })

                                })
                            }

                        } else {
                            response.json({
                                status: '401',
                                response: "passwords don't match"
                            });
                        }
                    }
                })

            }
        });
    }
})

app.get('/api/home', (req, response) => {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    var agent = req.headers['user-agent']
    console.log('Got a GET /api/home request from: ' + ip);
    const token = req.cookies.token;
    if (!token) {
        console.log("No token")
        response.json({
            status: '400',
            response: "unauthorized"
        });
    } else {
        console.log("Got token")
        request.post({ url: 'https://auth.betahuhn.de/auth', form: { token: token, ip: ip, agent: agent } }, function(error, response2, body) {
            //console.log(response2.body)
            const res = JSON.parse(String(response2.body));
            if (res.status == 401) {
                console.log("Unauthorized")
                response.json({
                    status: '400',
                    response: "unauthorized"
                });
            } else if (res.status == 400) {
                response.json({
                    status: '400',
                    response: "unauthorized"
                });
            } else if (res.status == 404) {
                response.json({
                    status: '400',
                    response: "unauthorized"
                });
            } else if (res.status == 200) {
                console.log(res.name + " is authorized")
                response.json({
                    status: '200',
                    response: "authorized",
                    name: res.name,
                    email: res.email,
                    user_id: res.user_id
                });
            }
        });
    }
})

app.get('/api/logout', (request, response) => {
    var ip = request.headers['x-forwarded-for'] || request.connection.remoteAddress;
    console.log('Got a logout request from: ' + ip);
    const token = request.cookies.token
    if (!token) {
        console.log("No token")
        response.clearCookie('token', { domain: ".betahuhn.de" })
        return response.json({
            status: '200'
        });
    }
    response.clearCookie('token', { path: '/' })
    console.log("Token cleared")
    response.json({
        status: '200'
    });
});

app.get('/test', (request, response) => {
    var ip = request.headers['x-forwarded-for'] || request.connection.remoteAddress;
    console.log('Got a test request from: ' + ip);
    response.json({
        status: '200'
    });
});

function checkPasswd(passwd, user_id) {
    var sql = `SELECT passwd FROM userbase WHERE user_id = '${user_id}';`;
    return new Promise(function(resolve, reject) {
        connection.query(sql, function(error, result, fields) {
            //console.log(result[0].passwd)
            bcrypt.compare(passwd, result[0].passwd, function(err, res) {
                resolve(res);
            });
        });
    })
}

function parseIP(ip) {
    var api_url = "http://api.ipstack.com/" + ip + "?access_key=13d00619e2be5c0bf0891364f2288ee1"
    return new Promise(function(resolve, reject) {
        request.get(api_url, (error, response, body) => {
            const res = JSON.parse(String(response.body));
            resolve(res)
        });
    })

}

function checkEmailExist(email) {
    var sql = `SELECT * FROM userbase WHERE email = '${email}';`;
    return new Promise(function(resolve, reject) {
        connection.query(sql, function(error, result, fields) {
            resolve(result.length > 0)
        });
    })
}

function getUID(email) {
    var sql = `SELECT * FROM userbase WHERE email = '${email}';`;
    return new Promise(function(resolve, reject) {
        connection.query(sql, function(error, result, fields) {
            if (isEmpty(result)) {
                resolve(undefined);
            } else {
                resolve(result[0]);
            }
        });
    })
}

function getToken(token) {
    var sql = `SELECT * FROM userbase WHERE reset_token = '${token}';`;
    return new Promise(function(resolve, reject) {
        connection.query(sql, function(error, result, fields) {
            if (isEmpty(result)) {
                resolve(undefined);
            } else {
                resolve(result[0]);
            }
        });
    })
}

function isEmpty(obj) {
    for (var key in obj) {
        if (obj.hasOwnProperty(key))
            return false;
    }
    return true;
}

function validEmail(email) {
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
}

function mysql_real_escape_string(str) {
    return str.replace(/[\0\x08\x09\x1a\n\r"'\\\%]/g, function(char) {
        switch (char) {
            case "\0":
                return "\\0";
            case "\x08":
                return "\\b";
            case "\x09":
                return "\\t";
            case "\x1a":
                return "\\z";
            case "\n":
                return "\\n";
            case "\r":
                return "\\r";
            case "\"":
            case "'":
            case "\\":
            case "%":
                return "\\" + char; // prepends a backslash to backslash, percent,
                // and double/single quotes
        }
    });
}