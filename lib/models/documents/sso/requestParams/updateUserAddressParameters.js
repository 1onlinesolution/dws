const Address = require('../address');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class UpdateUserAddressParameters {
  constructor({
    user_id,
    address_id,
    line1,
    line2,
    line3,
    postCode,
    city,
    state,
    country,
    isDefault,
    isBilling,
    isShipping,
  } = {}) {
    this.user_id = user_id;
    this.address_id = address_id;
    this.address = new Address({
      user_id,
      line1,
      line2,
      line3,
      postCode,
      city,
      state,
      country,
      isDefault,
      isBilling,
      isShipping,
    });

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

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof UpdateUserAddressParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(parameters.user_id)) return new Error('invalid user identifier');
    if (!Validity.isValidString(parameters.address_id)) return new Error('invalid address identifier');
    return Address.checkForError(parameters.address);
  }
}

module.exports = UpdateUserAddressParameters;
