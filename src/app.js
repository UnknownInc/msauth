import session from 'cookie-session';
import { join } from 'path';
import { existsSync, readFileSync } from 'fs';
import express, { json, urlencoded } from 'express';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import logger from './logger.js';
import config from './config.js';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import initializeCache from './cache.js';
import getAuthRouter, {verifySessionTokens} from './auth/oauth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
app.config = config; 
app.cache=initializeCache(config);

//using the logger and its configured transports, to save the logs created by Morgan
const logStream = {
  write: (text) => {
    logger.info(text);
  }
}

app.log = logger;
app.use(morgan('tiny', { stream: logStream }));

// app.mailer = require('./mailer.js');
// app.db = require('./services/firebase').firestore;

app.disable('x-powered-by');
// const helmet = require('helmet');
// app.use(helmet())

app.use(json()); // for parsing application/json
app.use(urlencoded({ extended: true }));

app.use(express.static(join(__dirname, '../ui/build')));
app.use(express.static(join(__dirname, '../public')));

app.use(cookieParser(app.config.cookieSecret));
app.use(verifySessionTokens);

app.get('/ping', function(_req,res){
    res.status(200).send('pong');
})

app.get('/_buildinfo', function(_req, res){
  try {
  const jsondata=readFileSync(join(__dirname,"../BUILDINFO")).toString();
  const buildinfo = JSON.parse(jsondata);
  return res.json(buildinfo);
  } catch (e) {
    app.log.error(e);
    return res.send({});
  }
});

app.get('/_env', function(_req, res){
  return res.json(process.env);
})

import apiRouter from './api/index.js';
app.use('/api', apiRouter);

const authRouter = await getAuthRouter(config);
app.use(authRouter);

import openApiRouter from './openapi/index.js';
app.use(openApiRouter);

app.get('/*', function (req, res) {
  const indexfile=join(__dirname, '../ui/build', 'index.html');
  if (existsSync(indexfile)) {
    res.sendFile(indexfile);
  } else {
    res.json({headers:req.headers, sd: req.sessionData});
  }
});

export default app;