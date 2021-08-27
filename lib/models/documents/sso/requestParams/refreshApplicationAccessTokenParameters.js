const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class RefreshApplicationAccessTokenParameters {
  constructor({ refresh_token, api_client_id, api_client_secret } = {}) {
    this.refresh_token = refresh_token;
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
    return RefreshApplicationAccessTokenParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof RefreshApplicationAccessTokenParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(parameters.refresh_token)) return new Error('invalid refresh token');
    if (!Validity.isValidString(parameters.api_client_id)) return new Error('invalid client identifier');
    if (!Validity.isValidString(parameters.api_client_secret)) return new Error('invalid client secret');
    return null;
  }
}

module.exports = RefreshApplicationAccessTokenParameters;
