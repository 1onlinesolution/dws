const Validity = require('../../../../tools/validity');

class CreateApiClientApplicationAuthorizationCodeParameters {
  constructor({ redirectUrl, clientId } = {}) {
    this.redirectUrl = redirectUrl;
    this.clientId = clientId;

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

  static checkForError(createApiClientAppCodeParameters) {
    if (!createApiClientAppCodeParameters || !(createApiClientAppCodeParameters instanceof CreateApiClientApplicationAuthorizationCodeParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(createApiClientAppCodeParameters.redirectUrl)) return new Error('invalid redirect URL');
    if (!Validity.isValidString(createApiClientAppCodeParameters.clientId)) return new Error('invalid client identifier');
    return null;
  }
}

module.exports = CreateApiClientApplicationAuthorizationCodeParameters;
