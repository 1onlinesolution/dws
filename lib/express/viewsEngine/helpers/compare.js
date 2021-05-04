module.exports.register = function (handlebars) {
  handlebars.registerHelper('compare', function(lvalue, rvalue, options) {
    if (arguments.length < 3) {
      throw new Error('Helper \'compare\' needs 2 parameters');
    }

    const operator = options.hash.operator || '===';

    // Code here will be linted with JSHint.
    /* jshint ignore:start */
    // Code here will be ignored by JSHint.
    const operators = {
      '==': function (l, r) {
        return l == r;
      },
      '===': function (l, r) {
        return l === r;
      },
      '!=': function (l, r) {
        return l != r;
      },
      '<': function (l, r) {
        return l < r;
      },
      '>': function (l, r) {
        return l > r;
      },
      '<=': function (l, r) {
        return l <= r;
      },
      '>=': function (l, r) {
        return l >= r;
      },
      typeof: function (l, r) {
        return typeof l == r;
      },
    };
    /* jshint ignore:end */

    if (!operators[operator]) {
      throw new Error('Handlerbars Helper \'compare\' doesn\'t know the operator ' + operator);
    }

    const result = operators[operator](lvalue, rvalue);

    if (result) {
      return options.fn(this);
    } else {
      return options.inverse(this);
    }
  });
};