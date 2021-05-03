const Address = require('./address');

class AddressItem {
  constructor({ address = new Address(), isDefault = false, isBilling = false, isShipping = false } = {}) {
    this.address = address;
    this.isDefault = isDefault;
    this.isBilling = isBilling;
    this.isShipping = isShipping;

    const error = this.checkForError();
    if (error) throw error;
    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return AddressItem.checkForError(this);
  }

  static checkForError(addressItem) {
    if (!addressItem || !(addressItem instanceof AddressItem)) return new Error('invalid address item');
    const error = Address.checkForError(addressItem.address);
    if (error) return error;
    return null;
  }
}

module.exports = AddressItem;
