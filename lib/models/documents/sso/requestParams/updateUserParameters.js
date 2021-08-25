const Validity = require('@1onlinesolution/dws-utils/lib/validity');
const Converter = require('@1onlinesolution/dws-utils/lib/converter');

class UpdateUserParameters {
  constructor({ user_id, firstName, lastName, newsletter } = {}) {
    this.user_id = user_id;
    this.firstName = firstName;
    this.lastName = lastName;
    this.newsletter = Converter.toBoolean(newsletter, false); // If options.newsletter is undefined, set to true

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return UpdateUserParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof UpdateUserParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(parameters.user_id)) return new Error('invalid user identifier');
    if (!Validity.isValidString(parameters.firstName)) return new Error('invalid firstName');
    if (!Validity.isValidString(parameters.lastName)) return new Error('invalid lastName');
    return null;
  }
}

module.exports = UpdateUserParameters;
