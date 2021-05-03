const ms = require('./ms');

class Converter {
  static toBoolean(value, ifUndefinedSetToFalse = true) {
    // Javascript way
    // if (typeof value === 'undefined') return !ifUndefinedSetToFalse;
    // return Boolean(value); (or !!value)
    if (typeof value === 'boolean') {
      return value;
    } else if (typeof value === 'undefined') {
      return !ifUndefinedSetToFalse;
    } else if (typeof value === 'string') {
      const trueValues = ['true', '1', 'on'];
      return trueValues.includes(value.toLowerCase());
    }

    return false;
  }

  static ms(value, options) {
    return ms(value, options);
  }

  static toSeconds(value, options) {
    return Converter.ms(value, options) / 1000;
  }

  static checkBoxToBoolean(value, valueExpected) {
    if (typeof value === 'undefined') {
      return false;
    } else if (typeof value === 'string') {
      const textLowerCase = valueExpected.toLowerCase();
      return value.toLowerCase() === textLowerCase;
    }

    return false;
  }
}

module.exports = Converter;
