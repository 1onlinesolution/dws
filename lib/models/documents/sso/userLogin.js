const Validity = require('../../../tools/validity');
const DateTimeUtils = require('../../../tools/dateTimeUtils');

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class UserLogin {
  constructor({ _id = null, email = null, ip = null, application = null, createdAt = null } = {}) {
    this._id = _id;
    this.email = email;
    this.ip = ip;
    this.application = application;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.createdAt = createdAt || nowUtc;

    const error = this.checkForError();
    if (error) throw error;
    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return UserLogin.checkForError(this);
  }

  static checkForError(userLogin) {
    if (!userLogin || !(userLogin instanceof UserLogin)) return new Error('invalid user login');
    if (!Validity.isValidEmail(userLogin.email)) return new Error('invalid user email address');
    if (!Validity.isValidString(userLogin.ip)) return new Error('invalid IP address');
    if (!Validity.isValidString(userLogin.application)) return new Error('invalid application');
    return null;
  }

  static get indexMap() {
    const createIndexName = (postfix) => `index_userLogin_${postfix}`;

    const map = new Map();
    map
      .set(createIndexName('email_application'), {
        fieldOrSpec: { email: 1, application: 1 },
        options: {
          name: createIndexName('email_application'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('ip'), {
        fieldOrSpec: { ip: 1 },
        options: {
          name: createIndexName('ip'),
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

module.exports = UserLogin;