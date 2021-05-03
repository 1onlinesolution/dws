const EmailParameters = require('./emailParameters');
const Converter = require('../../../../tools/converter');
const Validity = require('../../../../tools/validity');

class CreateUserParameters extends EmailParameters {
  constructor({ ip, host, firstName, lastName, userName, email, password, application, license, autoVerify, newsletter } = {}) {
    super({ ip, host });

    this.firstName = firstName;
    this.lastName = lastName;
    this.userName = userName;
    this.email = email;
    this.password = password;
    this.application = application;

    this.license = license;

    this.autoVerify = Converter.toBoolean(autoVerify, false); // If options.autoVerify is undefined, set to true
    this.newsletter = Converter.toBoolean(newsletter, false); // If options.newsletter is undefined, set to true

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  get emailParameters() {
    return {
      ip: this.ip,
      host: this.host,
    };
  }

  checkForError() {
    return CreateUserParameters.checkForError(this);
  }

  static checkForError(createUserParameters) {
    if (!createUserParameters || !(createUserParameters instanceof CreateUserParameters)) {
      return new Error('invalid parameters');
    }

    const error = EmailParameters.checkForError(createUserParameters);
    if (error) return error;
    if (!Validity.isValidString(createUserParameters.firstName)) return new Error('invalid firstName');
    if (!Validity.isValidString(createUserParameters.lastName)) return new Error('invalid lastName');
    if (!Validity.isValidString(createUserParameters.userName, 6)) return new Error('invalid user name');
    if (!Validity.isValidEmail(createUserParameters.email)) return new Error('invalid email');
    if (!Validity.isValidString(createUserParameters.password, 8)) return new Error('invalid password');
    if (!Validity.isValidString(createUserParameters.application)) return new Error('invalid application');
    return null;
  }
}

module.exports = CreateUserParameters;
