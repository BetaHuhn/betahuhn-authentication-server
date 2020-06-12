const log = require("../utils/log");
const crypto = require('crypto')

const sendResult = function(res, result, code) {
    res.status(code).json({
        status: code,
        time: new Date(),
        result: result,
    });
}

const routeLog = function() {
    return (req, res, next) => {
        const date_ob = new Date();
        const date = ('0' + date_ob.getDate()).slice(-2);
        const month = ('0' + (date_ob.getMonth() + 1)).slice(-2);
        const year = date_ob.getFullYear();
        const hours = date_ob.getHours();
        const minutes = date_ob.getMinutes();
        const seconds = date_ob.getSeconds();
        const time = year + '-' + month + '-' + date + ' ' + hours + ':' + minutes + ':' + seconds;
        log.request(`${time} ${req.method} ${req.originalUrl}`)
        next()
    };
}

const clientID = function() {
    return (req, res, next) => {
        const userAgent = req.get('user-agent')
        const language = req.headers['accept-language']
        const data = {
            userAgent: userAgent,
            language: language
        }
        const cid = crypto.createHash('md5').update(String(userAgent + language)).digest("hex");
        req.clientInfo = data;
        req.cid = cid;
        log.info("Generated CID: " + cid)
        next()
    }
}

module.exports = {
    sendResult: sendResult,
    routeLog: routeLog,
    clientID: clientID
}