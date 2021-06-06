import app from './app.js';
import { join } from 'path';
import { existsSync, readFileSync } from 'fs'
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);


;(async ()=>{

  const server = app.listen(app.config.PORT, () => {
      app.log.info(`PSI MSAUTH server app listening at port:${app.config.PORT}`); 
      try {
        const builddata=readFileSync(join(__dirname,"../BUILDINFO")).toString();
        app.log.info(builddata)
      } catch (e) {
        app.log.error(e);
      }
  });

  function onSIGHUP(signal) {
    console.log(`*^!@4=> Received event: ${signal}`);

  }

  function closeGracefully(signal) {
    console.log(`*^!@4=> Received event: ${signal}`);
    server.close(async ()=>{
      process.exit();
    });
  }

  process.on('SIGHUP', onSIGHUP);
  process.on('SIGINT', closeGracefully);
  process.on('SIGTERM', closeGracefully);
})().catch(err => console.log(err.stack))