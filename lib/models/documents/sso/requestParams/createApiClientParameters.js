const Validity = require('../../../../tools/validity');

class CreateApiClientParameters {
  constructor({ email } = {}) {
    this.email = email;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return CreateApiClientParameters.checkForError(this);
  }

  static checkForError(createApiClientParameters) {
    if (!createApiClientParameters || !(createApiClientParameters instanceof CreateApiClientParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidEmail(createApiClientParameters.email)) return new Error('invalid email');
    return null;
  }
}

module.exports = CreateApiClientParameters;
