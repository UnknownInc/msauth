import crypto from 'crypto';
import axios from 'axios';
import qs from 'qs';
import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import {URL} from 'url';

const SSID_COOKIE_NAME = 'ssid';

const base64URLEncode = (str) => str.toString('base64')
.replace(/\+/g, '-')
.replace(/\//g, '_')
.replace(/=/g, '');

const sha256 = (buffer) => crypto.createHash('sha256')
.update(buffer)
.digest();

const getDomainRoot = (host)=>{
  const parts=host.split('.');
  if (parts.length<3) return;
  return `${parts[1]}.${parts[2]}`;
}

const getReturnUrl = (rurl)=>{
  try {
    const ru = new URL(rurl);
    // const cu = new URL((req.headers['x-forwarded-proto']||req.protocol) +
    //   "://" + req.headers.host + req.originalUrl);
    if (!ru.hostname) {
      return rurl;
    }
    const allowedReturnhostnames = process.env.RETURN_HOSTS.split(',');
    if (allowedReturnhostnames.indexOf(ru.hostname.toLocaleLowerCase)!==-1) {
      return rurl;
    }
  } catch(ex) {
    console.error(`error parsing retrurnurl: ${ex}`)
  }
  return '/';
}

export const verifySessionTokens = async (req, res, next)=>{
  const {log, cache, config} = req.app;
  const ssid = req.signedCookies[SSID_COOKIE_NAME];
  if (!ssid) { 
    log.info('No Session');
    req.sessionData=null; 
    return next(); 
  }

  try {
    const sessionData = await cache.getAsync(ssid);
    if (!sessionData) {
      console.log(`Invalid session id: ${ssid}`);
      req.sessionData=null;
      res.clearCookie(SSID_COOKIE_NAME);
      return next();
    }

    if (Date.now() < sessionData.expiresAt) {
      req.sessionData = sessionData;
      return next();
    }

    const data = {
      grant_type: 'refresh_token',
      client_id: req.app.config.client_id,
      client_secret: req.app.config.client_secret,
      refresh_token: sessionData.tokenData.refresh_token
    }
    log.debug(`refreshing access_token: ${JSON.stringify(data)}`);
    const tokenResponse = await axios.post(`${sessionData.token_endpoint}`,
      qs.stringify(data));

    if (tokenResponse.status!==200) {
      log.error(`unable to refresh token. ${tokenResponse.data}`);
      cache.del(ssid);
      res.clearCookie(SSID_COOKIE_NAME);
      return next();
    }

    const tokenData = tokenResponse.data;
    if (!tokenData.access_token) {
      log.error(`invalid response on refreshing the token: ${tokenData.data}`);
      req.sessionData=null;
      return next();
    }

    sessionData.tokenData = tokenData;
    sessionData.expiresAt = Date.now() + tokenData.expires_in*1000;
    res.cookie(SSID_COOKIE_NAME, ssid, {
      signed: true,
      maxAge: config.sessionTimeout,
      secure: true,
      httpOnly: true,
      domain: getDomainRoot(req.headers.host)
    });
    cache.set(ssid, sessionData, {ttl: config.sessionTimeout}); 
    req.sessionData = sessionData;
    return next();
  } catch(ex) {
    log.error(ex);
    req.sessionData=null;
    return next();
  }
};

const getAuthRouter=async (config)=>{
  const router = Router();

  const client_id=config.client_id;
  const client_secret=config.client_secret;
  let OAuthConfig;
  
  try {
    const or = await axios.get(config.openidconfigurl);
    if (or.status!==200) {
      console.error(`unable to get openid configuration from ${config.openidconfigurl} \n ${or.status} - ${or.data}`);
      return router;
    }

    OAuthConfig = or.data;
    console.log(`fetched openid config from ${config.openidconfigurl}`);
  } catch (ex) {
    console.error(`unable to get openid configuration from ${config.openidconfigurl} \n ${ex}`);
    return router;
  }

  router.get('/login', function(req, res){
    const {log, cache} = req.app;
    const state=base64URLEncode(crypto.randomBytes(16));
    const code_verifier = base64URLEncode(crypto.randomBytes(32));

    cache.set(state, {code_verifier, returnUrl: getReturnUrl(req.query.returnUrl)});

    const scopes =  [...(req.query.scopes||'').split(','),...OAuthConfig.scopes_supported].join('%20');
    log.info(`login for scopes: ${scopes}`);

    res.clearCookie(SSID_COOKIE_NAME);
    if (req.sessionData) {
      cache.del(req.sessionData.id);
    }
    const code_challenge = base64URLEncode(sha256(code_verifier));
    const url = [
        `${OAuthConfig.authorization_endpoint}?`,
        `client_id=${client_id}&`,
        `scope=${scopes}&`,
        `response_type=code&`,
        `redirect_uri=${(req.headers['x-forwarded-proto']||req.protocol)+"://"+req.headers['host']+'/callback'}&`,
        `code_challenge=${code_challenge}&`,
        `code_challenge_method=S256&`,
        `state=${state}`
      ].join('');
      res.redirect(url);
  });

  router.get('/callback', async (req, res)=>{
    const {code, state, error, error_description} = req.query;
    const {cache, config, log} = req.app;

    if (error) {
      log.error({error, error_description});
      return res.json({error, error_description});
    }
    try {
      const {code_verifier, returnUrl} = await cache.getAsync(state);
      cache.del(state);
      const redirect_uri=(req.headers['x-forwarded-proto']||req.protocol)+"://"+req.headers.host+'/callback';
      const tokenResponse = await axios.post(`${OAuthConfig.token_endpoint}`,qs.stringify({
          grant_type: 'authorization_code',
          client_id,
          redirect_uri,
          client_secret,
          code_verifier,
          code,
      }));

      if (tokenResponse.status!==200) {
        console.error({status:tokenResponse.status, data:tokenResponse.data});
        return res.status(tokenResponse.status).json({error:'Invalid response from the selected login provider.'})
      }

      const tokenData = tokenResponse.data;

      const userInfoResponse = await axios.get(OAuthConfig.userinfo_endpoint,{
        headers:{
          Authorization: `Bearer ${tokenData.access_token}`
        }
      });

      if (userInfoResponse.status!==200) {
        console.error({status:userInfoResponse.status, data:userInfoResponse.data});
        return res.redirect("/");
      }

      const sessionId = "ac."+base64URLEncode(sha256(uuidv4()));

      res.cookie(SSID_COOKIE_NAME, sessionId, {
        signed: true,
        maxAge: config.sessionTimeout,
        secure: true,
        httpOnly: true,
        domain: getDomainRoot(req.headers.host)
      });
      cache.set(sessionId, {
        id: sessionId,
        expiresAt: Date.now()+(tokenData.expires_in-1)*1000,
        tokenData,
        userInfo: userInfoResponse.data,
        ua: req.headers['user-agent'],
        token_endpoint: OAuthConfig.token_endpoint,
      }, {ttl: config.sessionTimeout});
      return res.redirect(returnUrl);
    } catch(ex) {
      console.error(ex);
      return res.status(500).json({error:'Unable to authenticate.'});
    }
  });

  router.get('/logout', (req, res)=>{
    res.clearCookie(SSID_COOKIE_NAME);
    if (req.sessionData) {
      req.app.cache.del(req.sessionData.id);
    }
    const returnUrl = req.query.returnUrl||'/';
    return res.redirect(returnUrl);
  })

  return router;
}

export default getAuthRouter;