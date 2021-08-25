const EmailParameters = require('./emailParameters');

class EmailUserParameters extends EmailParameters {
  constructor({ ip, host, user } = {}) {
    super({ ip, host });
    this.user = user;

    if (new.target === EmailUserParameters) {
      const error = this.checkForError();
      if (error) throw error;
    }

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return EmailUserParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters) return new Error('invalid email user parameters');

    const error = EmailParameters.checkForError(parameters);
    if (error) return error;
    if (!parameters.user) return new Error('invalid user');
    return null;
  }
}

module.exports = EmailUserParameters;
