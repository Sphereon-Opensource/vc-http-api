import http from 'http';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import bodyParser from 'body-parser';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yamljs';
import middleware from './middleware';
import api from './api';
import config from './config.json';
import passport from './middleware/passport';
import initializeDb from './db';

let app = express();
app.server = http.createServer(app);

// logger
app.use(morgan('dev'));

// 3rd party middleware
app.use(cors({
    exposedHeaders: config.corsHeaders
}));

app.use(bodyParser.json({
    limit: config.bodyLimit
}));

// internal middleware
app.use(middleware({config}));

// database
initializeDb();

// authentication
app.use(passport.initialize());

// swagget ui
app.use('/docs', swaggerUi.serve, swaggerUi.setup(YAML.load('./src/resources/vc-http-api.yaml')));

// api router
app.use('/services', api({config}));

app.server.listen(process.env.PORT || config.port, () => {
    console.log(`Started on port ${app.server.address().port}`);
});

export default app;
