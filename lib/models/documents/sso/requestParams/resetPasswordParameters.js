const Validity = require('../../../../tools/validity');
const EmailUserParameters = require('./emailUserParameters');

class ResetPasswordParameters extends EmailUserParameters {
  constructor({ ip, host, user, password } = {}) {
    super({ ip, host, user });
    this.password = password;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return ResetPasswordParameters.checkForError(this);
  }

  static checkForError(resetPasswordParameters) {
    if (!resetPasswordParameters || !(resetPasswordParameters instanceof ResetPasswordParameters)) {
      return new Error('invalid parameters');
    }

    const error = EmailUserParameters.checkForError(resetPasswordParameters);
    if (error) return error;

    if (!Validity.isValidString(resetPasswordParameters.password, 8)) return new Error('invalid password');
    return null;
  }
}

module.exports = ResetPasswordParameters;
