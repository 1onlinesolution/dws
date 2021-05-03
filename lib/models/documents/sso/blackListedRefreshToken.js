const DateTimeUtils = require('../../../tools/dateTimeUtils');
const Validity = require('../../../tools/validity');

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class BlackListedRefreshToken {
  constructor({ _id = null, ip = null, token = null, createdAt = null } = {}) {
    this._id = _id;
    this.ip = ip;
    this.token = token;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.createdAt = createdAt || nowUtc;

    const error = this.checkForError();
    if (error) throw error;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return BlackListedRefreshToken.checkForError(this);
  }

  static checkForError(blackListedRefreshToken) {
    if (!blackListedRefreshToken || !(blackListedRefreshToken instanceof BlackListedRefreshToken)) {
      return new Error('invalid black-listed refresh token');
    }
    if (!Validity.isValidString(blackListedRefreshToken.ip)) return new Error('invalid IP address');
    if (!Validity.isValidString(blackListedRefreshToken.token)) return new Error('invalid refresh token');
    return null;
  }

  static get indexMap() {
    const createIndexName = (postfix) => `index_blackListedRefreshToken_${postfix}`;

    const map = new Map();
    map
      .set(createIndexName('token'), {
        fieldOrSpec: { token: 1 },
        options: {
          name: createIndexName('token'),
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

module.exports = BlackListedRefreshToken;
