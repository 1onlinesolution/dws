const { Validity, DateTimeUtils } = require('@1onlinesolution/dws-utils');

class EmailNotSent {
  constructor({
    _id = null,
    ip = null,
    user = null,
    application_name = null,
    message = null,
    error = null,
    created_at = null,
  } = {}) {
    this._id = _id;
    this.ip = ip;
    this.user = user;
    this.application_name = application_name;
    this.message = message;
    this.error = error;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.created_at = created_at || nowUtc;

    const checkError = this.checkForError();
    if (checkError) throw checkError;
    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return EmailNotSent.checkForError(this);
  }

  static checkForError(emailNotSent) {
    if (!emailNotSent || !(emailNotSent instanceof EmailNotSent)) return new Error('invalid parameters');
    if (!Validity.isValidString(emailNotSent.ip)) return new Error('invalid IP address');
    if (!Validity.isObject(emailNotSent.user)) return new Error('invalid user');
    if (!Validity.isValidString(emailNotSent.application_name)) return new Error('invalid application name');
    if (!Validity.isObject(emailNotSent.message)) return new Error('invalid email message');
    if (!Validity.isValidString(emailNotSent.message.from)) return new Error('invalid email origin');
    if (!Validity.isValidString(emailNotSent.message.to)) return new Error('invalid email destination');
    if (!Validity.isValidString(emailNotSent.message.subject)) return new Error('invalid email subject');
    return null;
  }

  static get indexMap() {
    const createIndexName = (postfix) => `index_emailNotSent_${postfix}`;

    const map = new Map();
    map
      .set(createIndexName('ip_user'), {
        fieldOrSpec: { ip: 1, user: 1 },
        options: {
          name: createIndexName('ip_user'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('application_name'), {
        fieldOrSpec: { application_name: 1 },
        options: {
          name: createIndexName('application_name'),
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

module.exports = EmailNotSent;
