const ObjectId = require('mongodb').ObjectID;
const DateTimeUtils = require('../../../tools/dateTimeUtils');
const Validity = require('../../../tools/validity');

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class Address {
  constructor({
    _id = undefined, // the ObjectID
    line1 = '',
    line2 = '',
    line3 = '',
    postCode = '',
    city = '',
    state = '',
    country = '',
    isDefault = false,
    isBilling = false,
    isShipping = false,
    createdAt = undefined,
    modifiedAt = undefined,
  } = {}) {
    this._id = _id || new ObjectId().toString(); // the ObjectID
    this.line1 = line1;
    this.line2 = line2;
    this.line3 = line3;
    this.postCode = postCode;
    this.city = city;
    this.state = state;
    this.country = country;
    this.isDefault = isDefault;
    this.isBilling = isBilling;
    this.isShipping = isShipping;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.createdAt = createdAt || nowUtc;
    this.modifiedAt = modifiedAt || nowUtc;

    const error = this.checkForError();
    if (error) throw error;
    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  static id(address) {
    if (!address._id) return '';
    return address._id.toString();
  }

  toString() {
    let text = this.line1;
    if (text.length > 0 && this.line2) text = `${text}, ${this.line2}`;
    if (text.length > 0 && this.line3) text = `${text}, ${this.line3}`;
    if (text.length > 0 && this.postCode) text = `${text}, ${this.postCode}`;
    if (text.length > 0 && this.city) text = `${text}, ${this.city}`;
    if (text.length > 0 && this.state !== '') text = `${text}, ${this.state}`;
    if (text.length > 0 && this.country) text = `${text}, ${this.country}`;
    return text;
  }

  checkForError() {
    return Address.checkForError(this);
  }

  static checkForError(address) {
    if (!address || !(address instanceof Address)) return new Error('invalid address');

    if (!Validity.isValidString(address._id)) return new Error('invalid address identifier');

    const messageLine1 = 'invalid address: field \'line1\'';
    if (Validity.isUndefinedOrEmptyString(address.line1) && (Validity.isValidString(address.line2) || Validity.isValidString(address.line3)))
      return new Error(messageLine1);

    if (Validity.isValidString(address.line1) &&
      (Validity.isUndefinedOrEmptyString(address.postCode) ||
        Validity.isUndefinedOrEmptyString(address.city) ||
        Validity.isUndefinedOrEmptyString(address.country)))
      return new Error(messageLine1);

    if (address.country === 'US' && !Validity.isValidString(address.state, 2, 2))
      return new Error('invalid state');

    if (!Validity.isBoolean(address.isDefault) ||
      !Validity.isBoolean(address.isBilling) ||
      !Validity.isBoolean(address.isShipping))
      return new Error('Invalid address flags');
  }
}

module.exports = Address;
