const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class DeleteUserParameters {
  constructor({
    user_id,
  } = {}) {

    this.user_id = user_id;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return DeleteUserParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof DeleteUserParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(parameters.user_id)) return new Error('invalid user identifier');
    return null;
  }
}

module.exports = DeleteUserParameters;
