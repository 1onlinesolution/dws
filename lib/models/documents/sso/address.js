const Validity = require('../../../tools/validity');

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class Address {
  constructor({
    line1 = '',
    line2 = '',
    line3 = '',
    postCode = '',
    city = '',
    country = '',
    isDefault = false,
    isBilling = false,
    isShipping = false,
  } = {}) {
    this.line1 = line1;
    this.line2 = line2;
    this.line3 = line3;
    this.postCode = postCode;
    this.city = city;
    this.country = country;
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

  toString() {
    let text = this.line1;
    if (text.length > 0 && this.line2) text = `${text}, ${this.line2}`;
    if (text.length > 0 && this.line3) text = `${text}, ${this.line3}`;
    if (text.length > 0 && this.postCode) text = `${text}, ${this.postCode}`;
    if (text.length > 0 && this.city) text = `${text}, ${this.city}`;
    if (text.length > 0 && this.country) text = `${text}, ${this.country}`;
    return text;
  }

  checkForError() {
    return Address.checkForError(this);
  }

  static checkForError(address) {
    if (!address || !(address instanceof Address)) return new Error('invalid address');

    const messageLine1 = 'invalid address: field \'line1\'';
    if (Validity.isUndefinedOrEmptyString(address.line1) && (Validity.isValidString(address.line2) || Validity.isValidString(address.line3)))
      return new Error(messageLine1);
    if (Validity.isValidString(address.line1) &&
      (Validity.isUndefinedOrEmptyString(address.postCode) ||
        Validity.isUndefinedOrEmptyString(address.city) ||
        Validity.isUndefinedOrEmptyString(address.country)))
      return new Error(messageLine1);

    if (!Validity.isBoolean(address.isDefault) ||
      !Validity.isBoolean(address.isBilling) ||
      !Validity.isBoolean(address.isShipping))
      return new Error('Invalid address flags');
  }
}

module.exports = Address;
