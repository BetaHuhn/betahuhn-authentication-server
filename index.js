const express = require('express');
const bodyParser = require('body-parser');
require('dotenv').config();
const app = express();
const cookieParser = require('cookie-parser');
const cors = require('cors');
const compression = require('compression');
const helmet = require('helmet');
const statusCodes = require("./utils/status");
const { routeLog, sendResult } = require("./middleware/middleware");
const database = require('./database/database');
const log = require("./utils/log");

const authRouter = require('./router/auth')

app.use(express.static('public'));
app.use(express.json({ limit: '1mb' }));
app.use(routeLog())
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }))
app.use(helmet());
app.use(helmet.hidePoweredBy({ setTo: 'Nokia 3310' }));
app.use(compression());
app.use(cookieParser())
app.set('trust proxy', 1);

const corsOptions = {
    origin: '*',
    methods: ["GET", "POST", "OPTIONS"],
    preflightContinue: true,
    optionsSuccessStatus: 200
}
app.use(cors(corsOptions))
app.use(authRouter)

/**
 * Connect to database and listen to given port
 */
async function startServer() {
    try {
        await database.connect();
        const PORT = process.env.PORT || 3000;
        app.listen(PORT, () => log.success("listening on port " + PORT));

    } catch (err) {
        log.fatal("Server setup failed. Wrong server IP or authentication?");
        log.fatal(err);
        process.exit(1);
    }
}
startServer();

app.get('/ip', (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    sendResult(res, ip, statusCodes.OK)
});

app.use(function(req, res, next) {
    res.status(statusCodes.NOT_FOUND).render("../public/error/404/index.ejs");
});