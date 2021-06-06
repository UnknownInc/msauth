import crypto from 'crypto';
import axios from 'axios';
import qs from 'qs';
import { Router } from 'express';

const base64URLEncode = (str) => str.toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=/g, '');

const sha256 = (buffer) => crypto.createHash('sha256')
  .update(buffer)
  .digest();

// https://www.adaltas.com/en/2020/11/20/oauth-microservices-public-app/

const OAuthConfig ={
  issuer: "https://auth.psnext.info/",
  authorization_endpoint: "https://auth.psnext.info/auth",
  token_endpoint: "https://auth.psnext.info/token",
  jwks_uri: "https://auth.psnext.info/keys",
  userinfo_endpoint: "https://auth.psnext.info/userinfo",
  device_authorization_endpoint: "https://auth.psnext.info/device/code",
  grant_types_supported: [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  response_types_supported: [
    "code"
  ],
  subject_types_supported: [
    "public"
  ],
  id_token_signing_alg_values_supported: [
    "RS256"
  ],
  code_challenge_methods_supported: [
   "S256",
   "plain"
  ],
  scopes_supported: [
   "openid",
   "email",
  //  "groups",
   "profile",
   "offline_access"
  ],
  token_endpoint_auth_methods_supported: [
   "client_secret_basic"
  ],
  claims_supported: [
   "aud",
   "email",
   "email_verified",
   "exp",
   "iat",
   "iss",
   "locale",
   "name",
   "sub"
  ]
};

const client_id='pdr-app';
const client_secret='ZXhhbXJgBsZS1hcHAtc2VjcmV0';


const router = Router();


router.get('/login', function(req, res){
  const {cache} = req.app;
  const scopes = req.query.scopes || OAuthConfig.scopes_supported.join('%20');
  const state=base64URLEncode(crypto.randomBytes(16));
  const code_verifier = base64URLEncode(crypto.randomBytes(32));

  cache.set(state, code_verifier);

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
  //res.render('login', { user: req.user });
});

router.get('/callback', async (req, res)=>{
  const {code, state} = req.query;
  const {cache} = req.app;
  try {
    const code_verifier = await cache.getP(state);
    cache.del(state);
    const redirect_uri=`${req.protocol+"://"+req.headers['host']+'/callback'}`;
    const tokenResponse = await axios.post(`${OAuthConfig.token_endpoint}`,qs.stringify({
        grant_type: 'authorization_code',
        client_id,
        redirect_uri,
        client_secret,
        code_verifier,
        code,
    }));

    if (tokenResponse.status===200) {
      const tokenData = tokenResponse.data;
      // return res.json(tokenResponse.data);

      const userInfoResponse = await axios.get(OAuthConfig.userinfo_endpoint,{
        headers:{
          Authorization: `Bearer ${tokenData.access_token}`
        }
      });

      if (userInfoResponse.status===200) {
        res.cookie('AT', tokenData.access_token,{
          maxAge: tokenData.expires_in,
          // httpOnly: true
        });
        cache.set(tokenData.access_token,{
          tokenData,
          userInfo: userInfoResponse.data
        }, {ttl: tokenData.expires_in});
        return res.json({tokenData, userInfo:userInfoResponse.data});
      } else {
        console.error({status:userInfoResponse.status, data:userInfoResponse.data});
        return res.json(userInfoResponse.data);
      }
    } else {
      console.error({status:tokenResponse.status, data:tokenResponse.data});
      return res.status(tokenResponse.status).json({error:'Invalid response from the selected login provider.'})
    }
  } catch(ex) {
    console.error(ex);
    return res.status(500).json({error:'Unable to authenticate.'});
  }
})
export default router;