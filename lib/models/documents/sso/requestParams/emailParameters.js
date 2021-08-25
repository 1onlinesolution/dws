const Validity = require('@1onlinesolution/dws-utils/lib/validity');

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

  static checkForError(parameters) {
    if (!parameters) return new Error('invalid email parameters');
    if (!Validity.isValidString(parameters.ip)) return new Error('invalid IP address');
    if (!Validity.isValidString(parameters.host)) return new Error('invalid host');
    return null;
  }
}

module.exports = EmailParameters;
