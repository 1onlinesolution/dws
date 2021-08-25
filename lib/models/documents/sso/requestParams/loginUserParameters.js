const Validity = require('@1onlinesolution/dws-utils/lib/validity');
const EmailParameters = require('./emailParameters');

class LoginUserParameters extends EmailParameters {
  constructor({ ip, host, email, password, issueJwtTokens = false } = {}) {
    super({ ip, host });
    this.email = email;
    this.password = password;

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

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof LoginUserParameters)) return new Error('invalid parameters');

    const error = EmailParameters.checkForError(parameters);
    if (error) return error;
    if (!Validity.isValidEmail(parameters.email)) return new Error('invalid email address');
    if (!Validity.isValidString(parameters.password, 8)) return new Error('invalid password');
    return null;
  }
}

module.exports = LoginUserParameters;
