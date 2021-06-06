import crypto from 'crypto';
import axios from 'axios';
import qs from 'qs';
import { Router } from 'express';
import uuid from 'uuid';

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
export const verifySessionTokens = async (req, res, next)=>{
  const {log, cache, config} = req.app;
  const ssid = req.signedCookies[SSID_COOKIE_NAME];
  if (!ssid) { 
    log.info('No Session');
    delete req.sessionData; 
    return next(); 
  }

  try {
    const sessionData = await cache.getAsync(ssid);
    if (!sessionData) {
      console.log(`Invalid session id: ${ssid}`);
      delete req.sessionData;
      res.clearCookie(SSID_COOKIE_NAME);
      return next();
    }

    if (Date.now() < sessionData.expiresAt) {
      req.sessionData = sessionData;
      return next();
    }

    log.info('refreshing access_token');
    const client_id = req.app.config.client_id;
    const client_secret = req.app.config.secret;
    const refresh_token = sessionData.tokenData.refresh_token;

    const tokenResponse = await axios.post(`${sessionData.authorization_endpoint}`,qs.stringify({
        grant_type: 'refresh_token',
        client_id,
        client_secret,
        refresh_token
    }));

    if (tokenResponse.status!==200) {
      log.error(`unable to refresh token. ${tokenResponse.data}`);
      cache.del(ssid);
      res.clearCookie(SSID_COOKIE_NAME);
      return next();
    }

    const tokenData = tokenResponse.data;
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
    delete req.sessionData;
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

  // const OAuthConfig = {
  //   token_endpoint: "https://login.microsoftonline.com/d52c9ea1-7c21-47b1-82a3-33a74b1f74b8/oauth2/v2.0/token",
  //   token_endpoint_auth_methods_supported: [
  //     "client_secret_post",
  //     "private_key_jwt",
  //     "client_secret_basic"
  //   ],
  //   jwks_uri: "https://login.microsoftonline.com/d52c9ea1-7c21-47b1-82a3-33a74b1f74b8/discovery/v2.0/keys",
  //   response_modes_supported: [
  //     "query",
  //     "fragment",
  //     "form_post"
  //   ],
  //   subject_types_supported: [
  //     "pairwise"
  //   ],
  //   id_token_signing_alg_values_supported: [
  //     "RS256"
  //   ],
  //   response_types_supported: [
  //     "code",
  //     "id_token",
  //     "code id_token",
  //     "id_token token"
  //   ],
  //   scopes_supported: [
  //   "openid",
  //   "profile",
  //   "email",
  //   "offline_access"
  //   ],
  //   issuer: "https://login.microsoftonline.com/d52c9ea1-7c21-47b1-82a3-33a74b1f74b8/v2.0",
  //   request_uri_parameter_supported: false,
  //   userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo",
  //   authorization_endpoint: "https://login.microsoftonline.com/d52c9ea1-7c21-47b1-82a3-33a74b1f74b8/oauth2/v2.0/authorize",
  //   device_authorization_endpoint: "https://login.microsoftonline.com/d52c9ea1-7c21-47b1-82a3-33a74b1f74b8/oauth2/v2.0/devicecode",
  //   http_logout_supported: true,
  //   frontchannel_logout_supported: true,
  //   end_session_endpoint: "https://login.microsoftonline.com/d52c9ea1-7c21-47b1-82a3-33a74b1f74b8/oauth2/v2.0/logout",
  //   claims_supported: [
  //     "sub",
  //     "iss",
  //     "cloud_instance_name",
  //     "cloud_instance_host_name",
  //     "cloud_graph_host_name",
  //     "msgraph_host",
  //     "aud",
  //     "exp",
  //     "iat",
  //     "auth_time",
  //     "acr",
  //     "nonce",
  //     "preferred_username",
  //     "name",
  //     "tid",
  //     "ver",
  //     "at_hash",
  //     "c_hash",
  //     "email"
  //   ],
  //   tenant_region_scope: "NA",
  //   cloud_instance_name: "microsoftonline.com",
  //   cloud_graph_host_name: "graph.windows.net",
  //   msgraph_host: "graph.microsoft.com",
  //   rbac_url: "https://pas.windows.net"
  // };

  router.get('/login', function(req, res){
    const {log, cache} = req.app;
    const state=base64URLEncode(crypto.randomBytes(16));
    const code_verifier = base64URLEncode(crypto.randomBytes(32));
    cache.set(state, code_verifier);

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
        `redirect_uri=${req.protocol+"://"+req.headers['host']+'/callback'}&`,
        `code_challenge=${code_challenge}&`,
        `code_challenge_method=S256&`,
        `state=${state}`
      ].join('')
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
      const code_verifier = await cache.getAsync(state);
      cache.del(state);
      const redirect_uri=`${req.protocol+"://"+req.headers.host+'/callback'}`;
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

      const sessionId = base64URLEncode(sha256(uuid.v4()));

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
        authorization_endpoint: OAuthConfig.authorization_endpoint,
      }, {ttl: config.sessionTimeout});
      const returnUrl="/";
      return res.redirect(returnUrl);
    } catch(ex) {
      console.error(ex);
      return res.status(500).json({error:'Unable to authenticate.'});
    }
  });

  router.get('/logout', (req, res)=>{
    res.clearCookie(SSID_COOKIE_NAME);
    if (req.sessionData) {
      cache.del(req.sessionData.id);
    }
  })

  return router;
}

export default getAuthRouter;