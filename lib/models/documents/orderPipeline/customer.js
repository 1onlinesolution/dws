const { Validity, DateTimeUtils } = require('@1onlinesolution/dws-utils');

// https://github.com/microsoft/Windows-appsample-customers-orders-database/blob/master/ContosoModels/Customer.cs

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class Customer {
  constructor({ user_id, _id = null, created_at = null, modified_at = null } = {}) {
    this._id = _id || null; // the ObjectID
    this.user_id = user_id;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.created_at = created_at || nowUtc;
    this.modified_at = modified_at || nowUtc;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return Customer.checkForError(this);
  }

  static checkForError(customer) {
    if (!customer || !(customer instanceof Customer)) return new Error('invalid customer');
    if (!Validity.isValidString(customer.user_id)) return new Error('invalid user identifier');
    return null;
  }
}

module.exports = Customer;
