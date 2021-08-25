const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class CreateApiClientApplicationAuthorizationCodeParameters {
  constructor({ apiClientApplicationId, redirectUrl } = {}) {
    this.apiClientApplicationId = apiClientApplicationId;
    this.redirectUrl = redirectUrl;

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

    if (!Validity.isValidString(parameters.redirectUrl)) return new Error('invalid redirect URL');
    if (!Validity.isValidString(parameters.apiClientApplicationId)) return new Error('invalid API client application identifier');
    return null;
  }
}

module.exports = CreateApiClientApplicationAuthorizationCodeParameters;
