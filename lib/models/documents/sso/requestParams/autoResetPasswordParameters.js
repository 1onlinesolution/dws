const Validity = require('../../../../tools/validity');
const EmailParameters = require('./emailParameters');

class AutoResetPasswordParameters extends EmailParameters {
  constructor({ ip, host, token, password } = {}) {
    super({ ip, host });
    this.token = token;
    this.password = password;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return AutoResetPasswordParameters.checkForError(this);
  }

  static checkForError(autoResetPasswordParameters) {
    if (!autoResetPasswordParameters || !(autoResetPasswordParameters instanceof AutoResetPasswordParameters)) {
      return new Error('invalid parameters');
    }

    const error = EmailParameters.checkForError(autoResetPasswordParameters);
    if (error) return error;
    if (!Validity.isValidString(autoResetPasswordParameters.token)) return new Error('invalid token');
    if (!Validity.isValidString(autoResetPasswordParameters.password, 8)) return new Error('invalid password');
    return null;
  }
}

module.exports = AutoResetPasswordParameters;
