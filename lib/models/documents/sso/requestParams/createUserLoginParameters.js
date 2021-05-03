const Validity = require('../../../../tools/validity');
const DateTimeUtils = require('../../../../tools/dateTimeUtils');

class CreateUserLoginParameters {
  constructor({ ip, email, application, createdAt = undefined } = {}) {
    this.ip = ip;
    this.email = email;
    this.application = application;
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

  static checkForError(createUserLoginParameters) {
    if (!createUserLoginParameters || !(createUserLoginParameters instanceof CreateUserLoginParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(createUserLoginParameters.ip)) return new Error('invalid IP address');
    if (!Validity.isValidEmail(createUserLoginParameters.email)) return new Error('invalid email');
    if (!Validity.isValidString(createUserLoginParameters.application)) return new Error('invalid application');
    return null;
  }
}

module.exports = CreateUserLoginParameters;
