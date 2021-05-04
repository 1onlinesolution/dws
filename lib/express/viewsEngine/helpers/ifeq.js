// standard hbs equality check, pass in two values from template
// {{#ifeq keyToCheck data.myKey}} [requires an else blocking template regardless]
module.exports.register = function (handlebars) {
  handlebars.registerHelper('ifeq', function(a, b, options) {
    if (a == b) {
      // eslint-disable-line eqeqeq
      return options.fn(this);
    } else {
      return options.inverse(this);
    }
  });
};
