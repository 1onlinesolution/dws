const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class CreateApiClientApplicationParameters {
  constructor({
    api_client_id,
    application_name,
    application_description,
    website_url,
    return_url,
  } = {}) {

    this.api_client_id = api_client_id;
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
    return CreateApiClientApplicationParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof CreateApiClientApplicationParameters)) {
      return new Error('invalid parameters');
    }

    const {
      api_client_id,
      application_name,
      application_description,
      website_url,
      return_url,
    } = parameters;

    if (!Validity.isValidString(api_client_id, 2)) return new Error('invalid client identifier');
    if (!Validity.isValidString(application_name)) return new Error('invalid application name');
    if (!Validity.isValidString(application_description)) return new Error('invalid application description');
    if (!Validity.isValidString(website_url)) return new Error('invalid website URL');
    if (!Validity.isValidString(return_url)) return new Error('invalid return URL');
    return null;
  }
}

module.exports = CreateApiClientApplicationParameters;
