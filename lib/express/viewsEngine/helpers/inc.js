module.exports.register = function (handlebars) {
  handlebars.registerHelper('inc', function(value) {
    return parseInt(value) + 1;
  });
};
