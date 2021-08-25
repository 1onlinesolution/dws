const Validity = require('@1onlinesolution/dws-utils/lib/validity');
const DateTimeUtils = require('@1onlinesolution/dws-utils/lib/dateTimeUtils');

class CreateEmailNotSentParameters {
  constructor({ _id = null, ip = null, user = null, applicationName = null, message = null, error = null, createdAt = null } = {}) {
    this._id = _id;
    this.ip = ip;
    this.user = user;
    this.applicationName = applicationName;
    this.message = message;
    this.error = error;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.createdAt = createdAt || nowUtc;

    const checkError = this.checkForError();
    if (checkError) throw checkError;
    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return CreateEmailNotSentParameters.checkForError(this);
  }

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof CreateEmailNotSentParameters))
      return new Error('invalid parameters');

    const { ip, user, applicationName, message } = parameters;
    if (!Validity.isValidString(ip)) return new Error('invalid IP address');
    if (!Validity.isObject(user)) return new Error('invalid user');
    if (!Validity.isValidString(applicationName)) return new Error('invalid application name');
    if (!Validity.isObject(message)) return new Error('invalid email message');
    if (!Validity.isValidString(message.from)) return new Error('invalid email origin');
    if (!Validity.isValidString(message.to)) return new Error('invalid email destination');
    if (!Validity.isValidString(message.subject)) return new Error('invalid email subject');
    return null;
  }
}

module.exports = CreateEmailNotSentParameters;
