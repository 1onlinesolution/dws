const ApiClientApplication = require('../apiClientApplication');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class UpdateApiClientApplicationParameters {
  constructor({
    apiClientApplicationId,
    applicationName,
    applicationDescription,
    websiteUrl,
    returnUrl,
  } = {}) {

    this.apiClientApplicationId = apiClientApplicationId;
    this.owner_firstName = owner_firstName;
    this.owner_lastName = owner_lastName;
    this.owner_email = owner_email;
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
    return UpdateApiClientApplicationParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof UpdateApiClientApplicationParameters)) {
      return new Error('invalid parameters');
    }

    const {
      apiClientApplicationId,
      applicationName,
      applicationDescription,
      websiteUrl,
      returnUrl,
    } = parameters;

    if (!Validity.isValidString(apiClientApplicationId, ApiClientApplication.clientIdLength)) return new Error('invalid api client application identifier');
    if (!Validity.isValidString(applicationName)) return new Error('invalid application name');
    if (!Validity.isValidString(applicationDescription)) return new Error('invalid application description');
    if (!Validity.isValidString(websiteUrl)) return new Error('invalid website URL');
    if (!Validity.isValidString(returnUrl)) return new Error('invalid return URL');
    return null;
  }
}

module.exports = UpdateApiClientApplicationParameters;
