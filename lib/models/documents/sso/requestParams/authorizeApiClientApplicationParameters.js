const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class AuthorizeApiClientApplicationParameters {
  constructor({ authorization_code, api_client_id, api_client_secret } = {}) {
    this.authorization_code = authorization_code;
    this.api_client_id = api_client_id;
    this.api_client_secret = api_client_secret;

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

    if (!Validity.isValidString(parameters.authorization_code)) return new Error('invalid authorization code');
    if (!Validity.isValidString(parameters.api_client_id)) return new Error('invalid client identifier');
    if (!Validity.isValidString(parameters.api_client_secret)) return new Error('invalid client secret');
    return null;
  }
}

module.exports = AuthorizeApiClientApplicationParameters;
