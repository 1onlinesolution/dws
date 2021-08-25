const { Validity } = require('@1onlinesolution/dws-utils');

// https://github.com/microsoft/Windows-appsample-customers-orders-database/blob/master/ContosoModels/LineItem.cs

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class OrderItem {
  constructor(options = {}) {
    this._id = options._id || null; // the ObjectID
    this.product_id = options.product_id;
    this.order = options.order;
    this.product = options.product;
    this.quantity = options.quantity;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return OrderItem.checkForError(this);
  }

  static checkForError(orderItem) {
    if (!orderItem || !(orderItem instanceof OrderItem)) return new Error('invalid order item');
    if (!Validity.isValidString(orderItem.product_id)) return new Error('invalid product identifier');
    if (!orderItem.order) return new Error('invalid order item');
    if (!orderItem.product) return new Error('invalid product');
    if (!orderItem.quantity || +orderItem.quantity <= 0) return new Error('invalid quantity');
    return null;
  }
}

module.exports = OrderItem;
