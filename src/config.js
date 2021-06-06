const config = {
    PORT: process.env.PORT || 8800,
    cookieSecret: process.env.COOKIE_SECRET,
    jwtSecret: process.env.JWT_SECRET,
    sessionTimeout: process.env.SESSION_TIMEOUT||(7*24*60*60*1000),

    openidconfigurl: process.env.OPENID_CONFIG_URL,
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,

    redisHost: process.env.REDIS_HOST,
    redisPort: process.env.REDIS_PORT,
    redisPassword: process.env.REDIS_PASSWORD,
    redisDB: process.env.REDIS_DB
};

export default config;