const DateTimeUtils = require('../../../tools/dateTimeUtils');
const Validity = require('../../../tools/validity');

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class ApiClient {
  constructor({ _id = null, email = null, applications = [], createdAt = null, modifiedAt = null } = {}) {
    this._id = _id;
    this.email = email;
    this.applications = applications;

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

  checkForError() {
    return ApiClient.checkForError(this);
  }

  static checkForError(apiClient) {
    if (!apiClient || !(apiClient instanceof ApiClient)) return new Error('invalid API client details');
    if (!Validity.isValidEmail(apiClient.email)) return new Error('invalid email address');
    return null;
  }

  static get indexMap() {
    const createIndexName = (postfix) => `index_apiClient_${postfix}`;

    const map = new Map();
    map
      .set(createIndexName('email_applications_applicationName'), {
        fieldOrSpec: { email: 1, 'applications.applicationName': 1 },
        options: {
          name: createIndexName('email_applications_applicationName'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('email_applications_clientId'), {
        fieldOrSpec: { email: 1, 'applications.clientId': 1 },
        options: {
          name: createIndexName('email_applications_clientId'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('applications_applicationName_clientId'), {
        fieldOrSpec: { 'applications.applicationName': 1, 'applications.clientId': 1 },
        options: {
          name: createIndexName('applications_applicationName_clientId'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('applications_clientId'), {
        fieldOrSpec: { 'applications.clientId': 1 },
        options: {
          name: createIndexName('applications_clientId'),
          unique: true,
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
      });

    return map;
  }
}

module.exports = ApiClient;
