const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class AuthorizeApiClientApplicationParameters {
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
    return AuthorizeApiClientApplicationParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof AuthorizeApiClientApplicationParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(parameters.authorizationCode)) return new Error('invalid authorization code');
    if (!Validity.isValidString(parameters.clientId)) return new Error('invalid client identifier');
    if (!Validity.isValidString(parameters.clientSecret)) return new Error('invalid client secret');
    return null;
  }
}

module.exports = AuthorizeApiClientApplicationParameters;
