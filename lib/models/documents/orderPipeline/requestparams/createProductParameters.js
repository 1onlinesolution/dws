const Validity = require('@1onlinesolution/dws-utils/lib/validity');
const ProductFeature = require('../productFeature');
const ProductCategory = require('../productCategory');

class CreateProductParameters {
  constructor({ name, price, description = '', features = [], category = ProductCategory.generic, locked = false } = {}) {
    this.name = name;
    this.price = price;
    this.description = description;
    this.features = features;
    this.category = category;
    this.locked = locked;

    if (new.target === CreateProductParameters) {
      const error = this.checkForError();
      if (error) throw error;
    }

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return CreateProductParameters.checkForError(this);
  }

  static checkForError(createProductParameters) {
    if (!createProductParameters || !(createProductParameters instanceof CreateProductParameters)) {
      return new Error('invalid product parameters');
    }

    if (!Validity.isValidString(createProductParameters.name)) return new Error('invalid product name');
    if (!Validity.isValidCurrency(createProductParameters.price)) return new Error('invalid product price');
    if (!Validity.isValidString(createProductParameters.description, 0)) return new Error('invalid product description');
    if (!Validity.isValidNumber(createProductParameters.category, ProductCategory.min, ProductCategory.max))
      return new Error('invalid product category');
    if (!Validity.isBoolean(createProductParameters.locked)) return new Error('invalid product lock value');

    const errorMessage = 'invalid product features';
    if (!createProductParameters.features) return new Error(errorMessage);
    createProductParameters.features.forEach((item) => {
      const error = ProductFeature.checkForError(item);
      if (error) return error;
    });
    return null;
  }
}

module.exports = CreateProductParameters;
