const Validity = require('@1onlinesolution/dws-utils/lib/validity');
const DateTimeUtils = require('@1onlinesolution/dws-utils/lib/dateTimeUtils');

class CreateUserLoginParameters {
  constructor({ ip, email, createdAt = undefined } = {}) {
    this.ip = ip;
    this.email = email;
    this.createdAt = createdAt || DateTimeUtils.currentUtcDate();

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return CreateUserLoginParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof CreateUserLoginParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(parameters.ip)) return new Error('invalid IP address');
    if (!Validity.isValidEmail(parameters.email)) return new Error('invalid email');
    return null;
  }
}

module.exports = CreateUserLoginParameters;
