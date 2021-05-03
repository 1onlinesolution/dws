const Validity = require('../../../../tools/validity');

class RefreshApplicationAccessTokenParameters {
  constructor({ refreshToken, clientId, clientSecret } = {}) {
    this.refreshToken = refreshToken;
    this.clientId = clientId;
    this.clientSecret = clientSecret;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return RefreshApplicationAccessTokenParameters.checkForError(this);
  }

  static checkForError(refreshAppAccessTokenParameters) {
    if (!refreshAppAccessTokenParameters || !(refreshAppAccessTokenParameters instanceof RefreshApplicationAccessTokenParameters)) {
      return new Error('invalid parameters');
    }

    if (!Validity.isValidString(refreshAppAccessTokenParameters.refreshToken)) return new Error('invalid refresh token');
    if (!Validity.isValidString(refreshAppAccessTokenParameters.clientId)) return new Error('invalid client identifier');
    if (!Validity.isValidString(refreshAppAccessTokenParameters.clientSecret)) return new Error('invalid client secret');
    return null;
  }
}

module.exports = RefreshApplicationAccessTokenParameters;
