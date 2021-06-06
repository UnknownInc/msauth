import cacheManager from 'cache-manager';
import redisStore from 'cache-manager-ioredis';
import util from 'util';

function initializeCache(config) {
  let cache;
  if (config.redisHost) {
    cache = cacheManager.caching({
      store: redisStore,
      host: config.redisHost, 
      port: config.redisPort, 
      password: config.redisPassword,
      db: 0,
      ttl: 600
    });
    // listen for redis connection error event
    var redisClient = cache.store.getClient();

    redisClient.on('connect', ()=>{
      console.log('REDIS: connected')
    })
    redisClient.on('error', (error) => {
      console.error(`REDIS: ${error}`);
    });
  } else {
    cache = cacheManager.caching({
        store: 'memory',
        ttl: 600
    });
  }

  cache.getAsync=util.promisify(cache.get);
  cache.setAsync=(key, value,ttl)=>{
    return new Promise((resolve, reject)=>{
      cache.set(key, value, ttl, (err, data)=>{
        if (err) return reject(err);
        resolve(data);
      })
    });
  };
  return cache;
}

export default initializeCache;
