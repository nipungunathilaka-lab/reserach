const jwt = require('jsonwebtoken');
const crypto = require('crypto');

exports.getInternalServiceToken = (reqMethod = "*", reqPath = "*") => {
    return jwt.sign(
        { 
            service: 'node-api',
            req_method: reqMethod,
            req_path: reqPath
        },
        process.env.INTERNAL_API_SECRET || 'default-insecure-internal-secret',
        { 
            expiresIn: '30s', 
            audience: 'fastapi-engine',
            issuer: 'node-api',
            jwtid: crypto.randomUUID()
        }
    );
};
