const { Validity, DateTimeUtils } = require('@1onlinesolution/dws-utils');
const ProductFeature = require('./productFeature');
const ProductCategory = require('./productCategory');

// https://github.com/microsoft/Windows-appsample-customers-orders-database/blob/master/ContosoModels/Product.cs

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class Product {
  constructor({
    _id = null, // the ObjectID
    name,
    description,
    price = 1.0,
    features = [],
    category = ProductCategory.generic,
    locked = false,
    created_at = null,
    modified_at = null,
  } = {}) {
    this._id = _id;
    this.name = name;
    this.description = description;
    this.price = price;
    this.features = features;
    this.category = category;
    this.locked = locked;

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
    return Product.checkForError(this);
  }

  static checkForError(product) {
    if (!product || !(product instanceof Product)) return new Error('invalid product');
    if (!Validity.isValidString(product.name)) return new Error('invalid product name');
    if (!Validity.isValidString(product.description, 0)) return new Error('invalid product description');
    if (!Validity.isValidCurrency(product.price)) return new Error('invalid product listed price');
    if (!Validity.isValidNumber(product.category, ProductCategory.min, ProductCategory.max)) return new Error('invalid product category');
    if (!product.features) return new Error('invalid product features');
    product.features.forEach((item) => {
      const error = ProductFeature.checkForError(item);
      if (error) return error;
    });
    return null;
  }

  static get indexMap() {
    const createIndexName = (postfix) => `index_product_${postfix}`;

    const map = new Map();
    map
      .set(createIndexName('name'), {
        fieldOrSpec: { name: 1 },
        options: {
          name: createIndexName('name'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('name_features_label'), {
        fieldOrSpec: { name: 1, 'features.label': 1 },
        options: {
          name: createIndexName('name_features_label'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('price'), {
        fieldOrSpec: { price: 1 },
        options: {
          name: createIndexName('price'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('category'), {
        fieldOrSpec: { category: 1 },
        options: {
          name: createIndexName('category'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('created_at'), {
        fieldOrSpec: { created_at: 1 },
        options: {
          name: createIndexName('created_at'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      });

    return map;
  }
}

module.exports = Product;
