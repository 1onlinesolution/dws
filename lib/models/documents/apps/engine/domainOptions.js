const Validity = require('@1onlinesolution/dws-utils/lib/validity');

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class DomainOptions {
  constructor({ masterDof = [0,0,0,0,0,0], coincidence = 1.0e-6 } = {}) {
    this.masterDof = masterDof;
    this.coincidence = coincidence;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return DomainOptions.checkForError(this);
  }

  static checkForError(domainOptions) {
    if (!domainOptions || !(domainOptions instanceof DomainOptions)) return new Error('invalid domain options');
    if (!domainOptions.masterDof) return new Error('invalid master degrees of freedom');
    if (!Validity.isValidNumber(domainOptions.coincidence)) return new Error('invalid coincidence');
    return null;
  }
}

module.exports = DomainOptions;
