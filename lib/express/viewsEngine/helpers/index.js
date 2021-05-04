const Handlebars = require('handlebars');

require('./code').register(Handlebars);
require('./currentYear').register(Handlebars);
require('./debug').register(Handlebars);
require('./for').register(Handlebars);
require('./is').register(Handlebars);
require('./lower').register(Handlebars);
require('./times').register(Handlebars);
require('./inc').register(Handlebars);
require('./dec').register(Handlebars);
require('./formatPostDate').register(Handlebars);
require('./ifeq').register(Handlebars);
require('./pagination').register(Handlebars);
require('./compare').register(Handlebars);

const helpers = {};

module.exports = helpers;
