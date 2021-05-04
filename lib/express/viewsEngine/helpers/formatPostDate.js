const moment = require('moment');

module.exports.register = function (handlebars) {
  handlebars.registerHelper('formatPostDate', function(date) {
    return moment(date).format('LL');
    // return moment(date).format('MMMM Do YYYY');
    // return moment(date).calendar();
  });
};
