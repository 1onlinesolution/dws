const EmailParameters = require('./emailParameters');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');
const Converter = require('@1onlinesolution/dws-utils/lib/converter');

class CreateUserParameters extends EmailParameters {
  constructor({ ip, host, company_name, first_name, last_name, user_name, email, password, license, auto_verify, newsletter } = {}) {
    super({ ip, host });

    this.company_name = company_name;
    this.first_name = first_name;
    this.last_name = last_name;
    this.user_name = user_name;
    this.email = email;
    this.password = password;

    this.license = license;

    this.auto_verify = Converter.toBoolean(auto_verify, false); // If options.auto_verify is undefined, set to true
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
    if (!Validity.isValidString(parameters.first_name)) return new Error('invalid first_name');
    if (!Validity.isValidString(parameters.last_name)) return new Error('invalid last_name');
    if (!Validity.isValidString(parameters.user_name, 6)) return new Error('invalid user name');
    if (!Validity.isValidEmail(parameters.email)) return new Error('invalid email');
    if (!Validity.isValidString(parameters.password, 8)) return new Error('invalid password');
    return null;
  }
}

module.exports = CreateUserParameters;
