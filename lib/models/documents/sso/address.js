const { Validity, DateTimeUtils } = require('@1onlinesolution/dws-utils');

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class Address {
  constructor({
    _id = undefined, // the ObjectID
    user_id = undefined,
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
    this._id = _id; // the ObjectID
    this.user_id = user_id;
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

    if (!Validity.isValidString(address.user_id)) return new Error('invalid user identifier');

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

  static get indexMap() {
    const createIndexName = (postfix) => `index_address_${postfix}`;
    const map = new Map();
    map
      .set(createIndexName('userId_country_city_postCode_line1'), {
        fieldOrSpec: { user_id: 1, country: 1, city: 1, postCode: 1, line1: 1 },
        options: {
          name: createIndexName('userId_country_city_postCode_line1'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('userId_country_state_city_postCode_line1'), {
        fieldOrSpec: { user_id: 1, country: 1, state: 1, city: 1, postCode: 1, line1: 1 },
        options: {
          name: createIndexName('userId_country_state_city_postCode_line1'),
          partialFilterExpression: { state: { $exists: true } },
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('country'), {
        fieldOrSpec: { country: 1 },
        options: {
          name: createIndexName('country'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('createdAt'), {
        fieldOrSpec: { createdAt: 1 },
        options: {
          name: createIndexName('createdAt'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('modifiedAt'), {
        fieldOrSpec: { modifiedAt: 1 },
        options: {
          name: createIndexName('modifiedAt'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      });

    return map;
  }
}

module.exports = Address;
