const mongoose = require('mongoose');

const server = '127.0.0.1:27017';
const database = process.env.DB_NAME;
const options = {
    user: process.env.DB_USERNAME,
    pass: process.env.DB_PASSWORD,
    keepAlive: true,
    keepAliveInitialDelay: 300000,
    useNewUrlParser: true,
    useUnifiedTopology: true
};
const url = `mongodb://${server}/${database}?authSource=${process.env.DB_AUTH}`

module.exports.connect = function() {

    mongoose.connect(url, options, )
        .then(() => {
            console.log('Database connection successfull: ' + database)
            return mongoose
        })
        .catch(err => {
            console.error('Fucked up while connecting to the database: ' + err)
            process.exit();
        })

    mongoose.connection.on('error', err => {
        console.error(err);
    });

}