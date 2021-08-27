const Validity = require('@1onlinesolution/dws-utils/lib/validity');
const Converter = require('@1onlinesolution/dws-utils/lib/converter');

class UpdateUserParameters {
  constructor({ user_id, first_name, last_name, newsletter } = {}) {
    this.user_id = user_id;
    this.first_name = first_name;
    this.last_name = last_name;
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
    if (!Validity.isValidString(parameters.first_name)) return new Error('invalid first_name');
    if (!Validity.isValidString(parameters.last_name)) return new Error('invalid last_name');
    return null;
  }
}

module.exports = UpdateUserParameters;
