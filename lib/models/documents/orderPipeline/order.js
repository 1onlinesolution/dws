const { Validity, DateTimeUtils } = require('@1onlinesolution/dws-utils');
const OrderStatus = require('./orderStatus');
const PaymentStatus = require('./paymentStatus');
const OrderTerm = require('./orderTerm');

// https://github.com/microsoft/Windows-appsample-customers-orders-database/blob/master/ContosoModels/Order.cs

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class Order {
  constructor(options = {}) {
    this._id = options._id || null; // the ObjectID
    this.customer_id = options.customer_id;
    this.customer = options.customer;
    this.customerName = options.customerName;
    this.invoiceNumber = options.invoiceNumber;
    this.address = options.address;
    this.orderItems = [];
    this.dateFilled = null;
    this.orderStatus = OrderStatus.open;
    this.paymentStatus = PaymentStatus.unpaid;
    this.taxFactor = options.taxFactor || 0.2;

    // the order's term
    this.term = options.term;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.datePlaced = options.datePlaced || nowUtc;
    this.created_at = options.created_at || nowUtc;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return Order.checkForError(this);
  }

  static checkForError(order) {
    if (!order || !(order instanceof Order)) return new Error('invalid order');
    if (!Validity.isValidString(order.customer_id)) return new Error('invalid customer identifier');
    if (!order.customer) return new Error('invalid customer');
    if (!Validity.isValidString(order.customerName)) return new Error('invalid customer name');
    if (!order.invoiceNumber) return new Error('invalid invoice number');
    if (!order.address) return new Error('invalid address');

    // TODO: proper number comparison required below
    if (!order.term || +order.term !== OrderTerm.month || +order.term !== OrderTerm.year) {
      return new Error('invalid term');
    }
    return null;
  }

  // Gets the order's subtotal.
  get subTotal() {
    // public decimal Subtotal => LineItems.Sum(lineItem => lineItem.Product.ListPrice * lineItem.Quantity);
    return this.orderItems.reduce((total, orderItem) => {
      return total + orderItem.product.price * orderItem.quantity;
    }, 0);
  }

  toString() {
    return `${this.invoiceNumber}`;
  }

  // Gets the order's tax.
  get tax() {
    return this.subTotal * this.taxFactor;
  }

  // Gets the order's grand total.
  get grandTotal() {
    return this.subTotal + this.tax;
  }
}

module.exports = Order;
