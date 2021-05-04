// lower.js
module.exports.register = function (handlebars) {
  handlebars.registerHelper('lower', function (text) {
    return String(text).toLowerCase();
  });
};
