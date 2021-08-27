const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class CreateApiClientApplicationAuthorizationCodeParameters {
  constructor({ api_client_id, api_client_application_id, redirect_url } = {}) {
    this.api_client_id = api_client_id;
    this.api_client_application_id = api_client_application_id;
    this.redirect_url = redirect_url;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return CreateApiClientApplicationAuthorizationCodeParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof CreateApiClientApplicationAuthorizationCodeParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(parameters.redirect_url)) return new Error('invalid redirect URL');
    if (!Validity.isValidString(parameters.api_client_id)) return new Error('invalid API client identifier');
    if (!Validity.isValidString(parameters.api_client_application_id)) return new Error('invalid API client application identifier');
    return null;
  }
}

module.exports = CreateApiClientApplicationAuthorizationCodeParameters;
