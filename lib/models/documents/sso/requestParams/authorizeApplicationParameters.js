const Validity = require('../../../../tools/validity');

class AuthorizeApplicationParameters {
  constructor({ authorizationCode, clientId, clientSecret } = {}) {
    this.authorizationCode = authorizationCode;
    this.clientId = clientId;
    this.clientSecret = clientSecret;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return AuthorizeApplicationParameters.checkForError(this);
  }

  static checkForError(authorizeApiClientApplication) {
    if (!authorizeApiClientApplication || !(authorizeApiClientApplication instanceof AuthorizeApplicationParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(authorizeApiClientApplication.authorizationCode)) return new Error('invalid authorization code');
    if (!Validity.isValidString(authorizeApiClientApplication.clientId)) return new Error('invalid client identifier');
    if (!Validity.isValidString(authorizeApiClientApplication.clientSecret)) return new Error('invalid client secret');
    return null;
  }
}

module.exports = AuthorizeApplicationParameters;
