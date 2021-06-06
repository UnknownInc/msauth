import { join } from 'path';

import { Router } from 'express';
const router = Router();


import { serve, setup } from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';


import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'PSNext',
      description: 'PSNext api specification',
      version: '0.1.0',
      license: {
        name: 'MIT'
      }
    },
  },
  apis: [ 
    join(__dirname, '../api/*.js'), 
    join(__dirname, './components.yaml')], // files containing annotations as above
};

const openapiSpecification = swaggerJsdoc(options);
router.use('/api-docs', function(req, _res, next){
    openapiSpecification.servers = [];
    if (req.get('host').indexOf('psnext.info')===-1){
      openapiSpecification.servers.push({
        url: `${req.protocol}://${req.get('host')}/api/`,
      })
    }
    openapiSpecification.servers=[
      ...openapiSpecification.servers,
      {
        url: `https://beta.psnext.info/api/`,
        description: "dev server"
      },{
        url: `https://www.psnext.info/api/`,
        description: "live server"
      }];
    req.swaggerDoc = openapiSpecification;
    next();
}, serve, setup(openapiSpecification, {
  // customCss: '.swagger-ui .topbar { display: none }',
  explorer: true,
  customSiteTitle: 'PSNEXT API Specification',
  //https://github.com/swagger-api/swagger-ui/blob/master/docs/usage/configuration.md
  opts:{
    url: '/api-docs.json'
  },
}));

// Serve swagger docs the way you like (Recommendation: swagger-tools)
router.get('/api-docs.json', (req, res) => {
  openapiSpecification.servers = [{
    url: `${req.protocol}://${req.get('host')}/api/`,
    description: "production server"
  }];
  res.setHeader('Content-Type', 'application/json');
  res.send(openapiSpecification);
});

export default router;



