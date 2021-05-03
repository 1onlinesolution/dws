const Validity = require('../../../../tools/validity');
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

  static checkForError(verifyUserTokenParameters) {
    if (!verifyUserTokenParameters || !(verifyUserTokenParameters instanceof VerifyUserTokenParameters)) return new Error('invalid parameters');

    const error = EmailParameters.checkForError(verifyUserTokenParameters);
    if (error) return error;

    if (!Validity.isValidString(verifyUserTokenParameters.token)) return new Error('invalid token');
    return null;
  }
}

module.exports = VerifyUserTokenParameters;
