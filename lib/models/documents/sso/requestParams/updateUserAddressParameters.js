const Address = require('../address');
const Validity = require('../../../../tools/validity');

class UpdateUserAddressParameters {
  constructor({ user_id, address_id, line1, line2, line3, postCode, city, state, country } = {}) {
    this.user_id = user_id;
    this.address_id = address_id;
    this.address = new Address({ line1, line2, line3, postCode, city, state, country });

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return UpdateUserAddressParameters.checkForError(this);
  }

  static checkForError(updateUserAddressParameters) {
    if (!updateUserAddressParameters || !(updateUserAddressParameters instanceof UpdateUserAddressParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(updateUserAddressParameters.user_id)) return new Error('invalid user identifier');
    if (!Validity.isValidString(updateUserAddressParameters.address_id)) return new Error('invalid address identifier');
    return Address.checkForError(updateUserAddressParameters.address);
  }
}

module.exports = UpdateUserAddressParameters;