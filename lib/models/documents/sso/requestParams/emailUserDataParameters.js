const EmailUserParameters = require('./emailUserParameters');

class EmailUserDataParameters extends EmailUserParameters {
  constructor({ ip, host, user, data } = {}) {
    super({ ip, host, user });
    this.data = data;

    if (new.target === EmailUserDataParameters) {
      const error = this.checkForError();
      if (error) throw error;
    }

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return EmailUserDataParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters) return new Error('invalid email user data');

    const error = EmailUserParameters.checkForError(parameters);
    if (error) return error;

    if (!parameters.data) return new Error('invalid data');
    return null;
  }
}

module.exports = EmailUserDataParameters;
