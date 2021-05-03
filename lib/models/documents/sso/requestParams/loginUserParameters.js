const Validity = require('../../../../tools/validity');
const EmailParameters = require('./emailParameters');

class LoginUserParameters extends EmailParameters {
  constructor({ ip, host, email, password, application, issueJwtTokens = false } = {}) {
    super({ ip, host });
    this.email = email;
    this.password = password;
    this.application = application;

    // If the user is logged in
    // and we just want to update the JWT tokens,
    // we simply set it to true
    this.issueJwtTokens = issueJwtTokens;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return LoginUserParameters.checkForError(this);
  }

  static checkForError(loginUserParameters) {
    if (!loginUserParameters || !(loginUserParameters instanceof LoginUserParameters)) return new Error('invalid parameters');

    const error = EmailParameters.checkForError(loginUserParameters);
    if (error) return error;
    if (!Validity.isValidEmail(loginUserParameters.email)) return new Error('invalid email address');
    if (!Validity.isValidString(loginUserParameters.password, 8)) return new Error('invalid password');
    if (!Validity.isValidString(loginUserParameters.application)) return new Error('invalid application');
    return null;
  }
}

module.exports = LoginUserParameters;
