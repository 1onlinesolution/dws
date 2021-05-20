const Address = require('../address');
const Validity = require('../../../../tools/validity');

class AddUserAddressParameters {
  constructor({ user_id, line1, line2, line3, postCode, city, country } = {}) {
    this.user_id = user_id;
    this.address = new Address({ user_id, line1, line2, line3, postCode, city, country });

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return AddUserAddressParameters.checkForError(this);
  }

  static checkForError(addUserAddressParameters) {
    if (!addUserAddressParameters || !(addUserAddressParameters instanceof AddUserAddressParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(addUserAddressParameters.user_id)) return new Error('invalid user identifier');
    return Address.checkForError(addUserAddressParameters.address);
  }
}

module.exports = AddUserAddressParameters;
