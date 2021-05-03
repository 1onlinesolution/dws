const Validity = require('../../../../tools/validity');

class CreateBlackListedRefreshTokenParameters {
  constructor({ ip, token } = {}) {
    this.ip = ip;
    this.token = token;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return CreateBlackListedRefreshTokenParameters.checkForError(this);
  }

  static checkForError(createBlackListedRefreshTokenParameters) {
    if (!createBlackListedRefreshTokenParameters ||
      !(createBlackListedRefreshTokenParameters instanceof CreateBlackListedRefreshTokenParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(createBlackListedRefreshTokenParameters.ip)) return new Error('invalid IP address');
    if (!Validity.isValidString(createBlackListedRefreshTokenParameters.token)) return new Error('invalid refresh token');
    return null;
  }
}

module.exports = CreateBlackListedRefreshTokenParameters;
