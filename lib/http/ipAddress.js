module.exports = (req) => {
  return req.ip ||
    req._remoteAddress ||
    req.headers['x-forwarded-for'] ||
    (req.connection && req.connection.remoteAddress) ||
    undefined;
};
