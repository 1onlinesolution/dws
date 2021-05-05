const session = require('./session');
module.exports = require('connect-mongo')(session);
