const Validity = require('../../../../tools/validity');

class CreateApiClientApplicationParameters {
  constructor({ email, applicationName, applicationDescription, websiteUrl, returnUrl } = {}) {
    this.email = email;
    this.applicationName = applicationName;
    this.applicationDescription = applicationDescription;
    this.websiteUrl = websiteUrl;
    this.returnUrl = returnUrl;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return CreateApiClientApplicationParameters.checkForError(this);
  }

  static checkForError(createApiClientApplicationParameters) {
    if (!createApiClientApplicationParameters || !(createApiClientApplicationParameters instanceof CreateApiClientApplicationParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidEmail(createApiClientApplicationParameters.email)) return new Error('invalid email address');
    if (!Validity.isValidString(createApiClientApplicationParameters.applicationName)) return new Error('invalid application name');
    if (!Validity.isValidString(createApiClientApplicationParameters.applicationDescription)) return new Error('invalid application description');
    if (!Validity.isValidString(createApiClientApplicationParameters.websiteUrl)) return new Error('invalid website URL');
    if (!Validity.isValidString(createApiClientApplicationParameters.returnUrl)) return new Error('invalid return URL');
    return null;
  }
}

module.exports = CreateApiClientApplicationParameters;
