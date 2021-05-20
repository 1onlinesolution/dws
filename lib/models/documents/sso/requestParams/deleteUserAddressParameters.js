const Address = require('../address');
const Validity = require('../../../../tools/validity');

class DeleteUserAddressParameters {
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
    return DeleteUserAddressParameters.checkForError(this);
  }

  static checkForError(deleteUserAddressParameters) {
    if (!deleteUserAddressParameters || !(deleteUserAddressParameters instanceof DeleteUserAddressParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(deleteUserAddressParameters.user_id)) return new Error('invalid user identifier');
    return Address.checkForError(deleteUserAddressParameters.address);
  }
}

module.exports = DeleteUserAddressParameters;