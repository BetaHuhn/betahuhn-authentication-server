const User = require('../models/user.js');
const md5 = require('md5');
const cache = require('memory-cache');

var routerCache = new cache.Cache();

module.exports = {
    auth: (rights) => {
        return async (req, res, next) => {
            try{
                const user = await User.isAuthorized(req.cookies.token)
                if(user.rights.admin && rights == "admin"){
                    req.user = user;
                    console.log(user.name + " is authorized")
                    next()
                }else if(user.rights.user && rights == "user"){
                    req.user = user;
                    console.log(user.name + " is authorized")
                    next()
                }else if(user.rights.moderator && rights == "moderator"){
                    req.user = user;
                    console.log(user.name + " is authorized")
                    next()
                }else{
                    console.log("not authorized")
                    res.json({
                        status: '403',
                        response: 'not authorized'
                    });
                }
            }catch(error){
                if(error.code == 401){
                    console.log("not authorized")
                    res.json({
                        status: '401',
                        response: 'not authorized'
                    });
                }else if(error.code == 402){
                    console.log("No token")
                    res.json({
                        status: '402',
                        response: 'not authorized'
                    });
                }else if(error.code == 405){
                    console.log("No user found")
                    res.json({
                        status: '405',
                        response: 'not authorized'
                    });
                }else{
                    console.log(error)
                    res.json({
                        status: '401',
                        response: 'not authorized'
                    });
                }
            } 
        }
    },
    cache: (duration) => {
        return (req, res, next) => {
            let key = md5(req.url + "__" + JSON.stringify(req.body))
            let cacheContent = routerCache.get(key);
            if(cacheContent){
                console.log("request " + key + " already in cache, sending last saved data")
                res.send( cacheContent );
                return
            }else{
                console.log("request " + key + " not in cache, querying database")
                res.sendResponse = res.send
                res.send = (body) => {
                    routerCache.put(key, body, duration*1000);
                    res.sendResponse(body)
                }
                next()
            }
        }
    },
    log: (duration) => {
        return (req, res, next) => {
            var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
            let date_ob = new Date();
            let date = ("0" + date_ob.getDate()).slice(-2);
            let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
            let year = date_ob.getFullYear();
            let hours = date_ob.getHours();
            let minutes = date_ob.getMinutes();
            let seconds = date_ob.getSeconds();
            let milli = date_ob.getMilliseconds();
            var time = year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds + "." + milli;
            console.log(time + " " + req.method + " " + req.originalUrl + ' request from: ' + ip);
            next()
        }
    }
}