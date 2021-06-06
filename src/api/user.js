import { Router } from 'express';
import axios from 'axios';

const userApiRouter = Router();

const requireSession=(req, res, next)=>{
  if (!req.sessionData) {
    return res.status(401).send();
  }
  next();
}

userApiRouter.get('/me/photo', requireSession, async (req, res, next)=>{
  const {log} = req.app;
  try {
    const result = await axios.get(req.sessionData.userInfo.picture, {
      responseType: 'arraybuffer',
      headers: {
        'User-Agent': req.sessionData.ua,
        'Authorization':`Bearer ${req.sessionData.tokenData.access_token}`,
        'Accept': req.headers['accept']
      }
    });

    if (result.status!==200) {
      log.error(result.status);
      log.error(result.data);
      return res.status(500).send({error:'Unknown error'});
    }

    res.set('content-type', result.headers['content-type']);
    return res.send(result.data);
  } catch (ex) {
    log.error(ex);
    return res.status(500).send({error:'Unknown error'});
  }
});


userApiRouter.get('/me/calendar', requireSession, async (req, res, next)=>{
  const {log} = req.app;
  try {
    const result = await axios.get(`https://graph.microsoft.com/v1.0/me/calendarview?startdatetime=2021-06-05T12:06:51.503Z&enddatetime=2021-06-12T12:06:51.503Z`, {
      headers: {
        'User-Agent': req.sessionData.ua,
        'Authorization':`Bearer ${req.sessionData.tokenData.access_token}`,
      }
    });

    if (result.status!==200) {
      log.error(result.status);
      log.error(result.data);
      return res.status(500).send({error:'Unknown error'});
    }

    res.set('content-type', result.headers['content-type']);
    return res.send(result.data);
  } catch (ex) {
    log.error(ex);
    return res.status(500).send({error:'Unknown error'});
  }
});

export default userApiRouter;