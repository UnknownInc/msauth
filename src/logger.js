import pkg from 'winston';
const { createLogger, format, transports } = pkg;
const { combine, splat, timestamp, printf } = format;

const logFormat = printf( ({ level, message, timestamp , ...metadata}) => {
  let msg = `${timestamp} [${level}] : ${message} `  
  if(metadata) {
    let ms = JSON.stringify(metadata);
    if (ms!=='{}') {
      msg += ms;
    }
  }
  return msg
});

const logger = createLogger({
  level: (process.env.LOGLEVEL || 'debug'),
  format: combine(
    format.colorize(),
    splat(),
    timestamp(),
    logFormat
  ),
  transports: [
      new (transports.Console)(),
      // new (winston.transports.File)({ filename: 'app.log'})
  ]
})

export default logger;