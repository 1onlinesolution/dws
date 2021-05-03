const Converter = require('../../../../tools/converter');
const Validity = require('../../../../tools/validity');

class UpdateUserParameters {
  constructor({ user_id, firstName, lastName, /*email, password,*/ newsletter } = {}) {
    this.user_id = user_id;
    this.firstName = firstName;
    this.lastName = lastName;
    // this.email = email;
    // this.password = password;
    this.newsletter = Converter.toBoolean(newsletter, false); // If options.newsletter is undefined, set to true

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  get emailParameters() {
    return {
      ip: this.ip,
      host: this.host,
    };
  }

  checkForError() {
    return UpdateUserParameters.checkForError(this);
  }

  static checkForError(updateUserParameters) {
    if (!updateUserParameters || !(updateUserParameters instanceof UpdateUserParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(updateUserParameters.user_id)) return new Error('invalid user identifier');
    if (!Validity.isValidString(updateUserParameters.firstName)) return new Error('invalid firstName');
    if (!Validity.isValidString(updateUserParameters.lastName)) return new Error('invalid lastName');
    // if (!Validity.isValidEmail(updateUserParameters.email)) return new Error('invalid email');
    // if (!Validity.isValidString(updateUserParameters.password, 8)) return new Error('invalid password');
    return null;
  }
}

module.exports = UpdateUserParameters;
