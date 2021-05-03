const Validity = require('../../../../tools/validity');
const DateTimeUtils = require('../../../../tools/dateTimeUtils');

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

  static checkForError(createEmailNotSentParameters) {
    if (!createEmailNotSentParameters || !(createEmailNotSentParameters instanceof CreateEmailNotSentParameters))
      return new Error('invalid parameters');
    if (!Validity.isValidString(createEmailNotSentParameters.ip)) return new Error('invalid IP address');
    if (!Validity.isObject(createEmailNotSentParameters.user)) return new Error('invalid user');
    if (!Validity.isValidString(createEmailNotSentParameters.applicationName)) return new Error('invalid application name');
    if (!Validity.isObject(createEmailNotSentParameters.message)) return new Error('invalid email message');
    if (!Validity.isValidString(createEmailNotSentParameters.message.from)) return new Error('invalid email origin');
    if (!Validity.isValidString(createEmailNotSentParameters.message.to)) return new Error('invalid email destination');
    if (!Validity.isValidString(createEmailNotSentParameters.message.subject)) return new Error('invalid email subject');
    return null;
  }
}

module.exports = CreateEmailNotSentParameters;
