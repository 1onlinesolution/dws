const Validity = require('@1onlinesolution/dws-utils/lib/validity');
const EmailParameters = require('./emailParameters');

class VerifyUserTokenParameters extends EmailParameters {
  constructor({ ip, host, token } = {}) {
    super({ ip, host });
    this.token = token;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return VerifyUserTokenParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof VerifyUserTokenParameters)) return new Error('invalid parameters');

    const error = EmailParameters.checkForError(parameters);
    if (error) return error;

    if (!Validity.isValidString(parameters.token)) return new Error('invalid token');
    return null;
  }
}

module.exports = VerifyUserTokenParameters;
