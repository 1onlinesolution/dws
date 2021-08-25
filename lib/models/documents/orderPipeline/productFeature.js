const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class ProductFeature {
  constructor({ label, description = '', on = false } = {}) {
    this.label = label;
    this.description = description;
    this.on = on;

    const error = this.checkForError();
    if (error) throw error;
    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return ProductFeature.checkForError(this);
  }

  static checkForError(productFeature) {
    if (!productFeature || !(productFeature instanceof ProductFeature)) return new Error('invalid product feature');
    if (!Validity.isValidString(productFeature.label)) return new Error('invalid product feature label');
    // Allow empty description
    // if (!Validity.isValidString(productFeature.description, 0)) return new Error('invalid product feature description');
    return null;
  }
}

module.exports = ProductFeature;
