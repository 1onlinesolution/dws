module.exports.register = function (handlebars) {
  handlebars.registerHelper('for', function (from, to, incr, block) {
    let accum = '';
    for (let i = from; i < to; i += incr) {
      accum += block.fn(i);
    }
    return accum;
  });
};