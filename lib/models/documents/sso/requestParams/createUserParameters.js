const EmailParameters = require('./emailParameters');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');
const Converter = require('@1onlinesolution/dws-utils/lib/converter');

class CreateUserParameters extends EmailParameters {
  constructor({ ip, host, firstName, lastName, userName, email, password, license, autoVerify, newsletter } = {}) {
    super({ ip, host });

    this.firstName = firstName;
    this.lastName = lastName;
    this.userName = userName;
    this.email = email;
    this.password = password;

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

  static checkForError(parameters) {
    if (!parameters || !(parameters instanceof CreateUserParameters)) {
      return new Error('invalid parameters');
    }

    const error = EmailParameters.checkForError(parameters);
    if (error) return error;
    if (!Validity.isValidString(parameters.firstName)) return new Error('invalid firstName');
    if (!Validity.isValidString(parameters.lastName)) return new Error('invalid lastName');
    if (!Validity.isValidString(parameters.userName, 6)) return new Error('invalid user name');
    if (!Validity.isValidEmail(parameters.email)) return new Error('invalid email');
    if (!Validity.isValidString(parameters.password, 8)) return new Error('invalid password');
    return null;
  }
}

module.exports = CreateUserParameters;
