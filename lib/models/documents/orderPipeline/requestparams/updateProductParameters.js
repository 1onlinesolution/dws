const CreateProductParameters = require('./createProductParameters');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class UpdateProductParameters extends CreateProductParameters {
  constructor({ _id, name, price, description, features, category, locked } = {}) {
    super({ name, price, description, features, category, locked });
    this._id = _id;

    const error = this.checkForError();
    if (error) throw error;
    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return UpdateProductParameters.checkForError(this);
  }

  static checkForError(updateProductParameters) {
    if (!updateProductParameters || !(updateProductParameters instanceof UpdateProductParameters)) {
      return new Error('invalid product parameters');
    }
    const error = CreateProductParameters.checkForError(new CreateProductParameters({...updateProductParameters}));
    if (error) throw error;
    if (!Validity.isValidString(updateProductParameters._id)) return new Error('invalid product identifier');
    return null;
  }
}

module.exports = UpdateProductParameters;
