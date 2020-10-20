import mongoose from 'mongoose';
import dbConfig from './resources/config/databaseConfig.json';

export default () => {
    //Set up default mongoose connection
    mongoose.connect(dbConfig.dbUrl, { useNewUrlParser: true, useUnifiedTopology: true });

    //Get the default connection
    const db = mongoose.connection;

    //Bind connection to error event (to get notification of connection errors)
    db.on('error', console.error.bind(console, 'MongoDB connection error:'));

    return db
}
