module.exports.register = function (handlebars) {
  handlebars.registerHelper('dec', function(value) {
    return parseInt(value) - 1;
  });
};
