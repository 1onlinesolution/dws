const Address = require('../address');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class CreateUserAddressParameters {
  constructor({
    user_id,
    line1,
    line2,
    line3,
    postCode,
    city,
    state,
    country,
    isDefault = false,
    isBilling = false,
    isShipping = false,
  } = {}) {
    this.user_id = user_id;
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
    return CreateUserAddressParameters.checkForError(this);
  }

  static checkForError(createUserAddressParameters) {
    if (!createUserAddressParameters || !(createUserAddressParameters instanceof CreateUserAddressParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(createUserAddressParameters.user_id)) return new Error('invalid user identifier');
    return Address.checkForError(createUserAddressParameters.address);
  }
}

module.exports = CreateUserAddressParameters;
