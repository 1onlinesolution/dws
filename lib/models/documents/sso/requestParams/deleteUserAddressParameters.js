const Validity = require('../../../../tools/validity');

class DeleteUserAddressParameters {
  constructor({ user_id, address_id } = {}) {
    this.user_id = user_id;
    this.address_id = address_id;

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
    if (!Validity.isValidString(deleteUserAddressParameters.address_id)) return new Error('invalid address identifier');
    return null;
  }
}

module.exports = DeleteUserAddressParameters;
