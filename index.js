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
const cors = require('cors')
const authRouter = require('./router/auth')
var compression = require('compression');
var helmet = require('helmet');

require('./database/database')

app.listen(2000, () => console.log('listening on port 2000'));
app.use(express.static('public'));
app.use(express.json({ limit: '1mb' }));
app.set("view engine", "ejs");
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(compression());
app.use(helmet());
app.use(authRouter)

app.use(
    cors({
        origin: "*",
        methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
        preflightContinue: false
    })
);

process.on('unhandledRejection', (reason, p) => {
    console.log("Unhandled Rejection at: Promise ", p, " reason: ", reason);
});
process.on('uncaughtException', (error) => {
    console.log('Shit hit the fan (uncaughtException): ', error);
    process.exit(1);
})

app.get('/test', (request, response) => {
    var ip = request.headers['x-forwarded-for'] || request.connection.remoteAddress;
    console.log('Got a test request from: ' + ip);
    response.json({
        status: '200',
        response: "GET request successfull"
    });
    const used = process.memoryUsage();
    for (let key in used) {
        console.log(`${key} ${Math.round(used[key] / 1024 / 1024 * 100) / 100} MB`);
    }
});

app.post('/test', (request, response) => {
    var ip = request.headers['x-forwarded-for'] || request.connection.remoteAddress;
    console.log('Got a test request from: ' + ip);
    response.json({
        status: '200',
        response: "POST request successfull"
    });
});

app.get('/ip', (req, res) => {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    console.log('Got a up request from: ' + ip);
    res.json({
        status: 200,
        ip: ip
    });
});

app.use(function(req, res, next) {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    let date_ob = new Date();
    let date = ("0" + date_ob.getDate()).slice(-2);
    let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
    let year = date_ob.getFullYear();
    let hours = date_ob.getHours();
    let minutes = date_ob.getMinutes();
    let seconds = date_ob.getSeconds();
    var time = year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds
    console.log(time + " " + req.method + " " + req.originalUrl + ' request from: ' + ip + " -> 404");
    res.status(404);
    res.send('404: File Not Found');
});