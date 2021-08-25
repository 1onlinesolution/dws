const ApiClientApplication = require('../apiClientApplication');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class DeleteApiClientApplicationParameters {
  constructor({
    apiClientApplicationId,
  } = {}) {

    this.apiClientApplicationId = apiClientApplicationId;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return DeleteApiClientApplicationParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof DeleteApiClientApplicationParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(parameters.apiClientApplicationId, ApiClientApplication.clientIdLength)) return new Error('invalid api client application identifier');
    return null;
  }
}

module.exports = DeleteApiClientApplicationParameters;
