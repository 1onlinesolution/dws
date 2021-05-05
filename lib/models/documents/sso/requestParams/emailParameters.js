const Validity = require('../../../../tools/validity');

class EmailParameters {
  constructor({ ip, host } = {}) {
    this.ip = ip;
    this.host = host;

    if (new.target === EmailParameters) {
      const error = this.checkForError();
      if (error) throw error;
    }

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return EmailParameters.checkForError(this);
  }

  static checkForError(emailParameters) {
    if (!emailParameters) return new Error('invalid email parameters');
    if (!Validity.isValidString(emailParameters.ip)) return new Error('invalid IP address');
    if (!Validity.isValidString(emailParameters.host)) return new Error('invalid host');
    return null;
  }
}

module.exports = EmailParameters;
