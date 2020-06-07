let mongoose = require('mongoose');
var password = require('../key.json').db

const server = '127.0.0.1:27017';
const database = 'users'; // REPLACE WITH MongDB DB NAME
const options = {
    user:"creerow",
    pass: password,
    keepAlive: true,
    keepAliveInitialDelay: 300000,
    useNewUrlParser: true,
    useUnifiedTopology: true
};

mongoose.connect(`mongodb://${server}/${database}?authSource=admin`, options, )
    .then(() => {
        console.log('Database connection successfull: ' + database)
    })
    .catch(err => {
        console.error('Fucked up while connecting to the database: ' + err)
        process.exit();
    })