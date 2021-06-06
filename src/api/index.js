import { Router } from 'express';

const apiRouter = Router();

import userApiRouter from './user.js'
apiRouter.use('/user', userApiRouter);

export default apiRouter;