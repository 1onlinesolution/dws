const ApiClientApplication = require('../apiClientApplication');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class UpdateApiClientApplicationParameters {
  constructor({
    api_client_application_id,
    application_name,
    application_description,
    website_url,
    return_url,
  } = {}) {

    this.api_client_application_id = api_client_application_id;
    this.application_name = application_name;
    this.application_description = application_description;
    this.website_url = website_url;
    this.return_url = return_url;

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
      api_client_application_id,
      application_name,
      application_description,
      website_url,
      return_url,
    } = parameters;

    if (!Validity.isValidString(api_client_application_id, ApiClientApplication.clientIdLength)) return new Error('invalid api client application identifier');
    if (!Validity.isValidString(application_name)) return new Error('invalid application name');
    if (!Validity.isValidString(application_description)) return new Error('invalid application description');
    if (!Validity.isValidString(website_url)) return new Error('invalid website URL');
    if (!Validity.isValidString(return_url)) return new Error('invalid return URL');
    return null;
  }
}

module.exports = UpdateApiClientApplicationParameters;
