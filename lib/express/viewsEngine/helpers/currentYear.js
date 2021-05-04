module.exports.register = function (handlebars) {
  handlebars.registerHelper('currentYear', function() {
    return new Date().getFullYear();
  });
};
