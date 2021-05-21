const Address = require('./address');
const UserRole = require('./userRole');
const UserStatistics = require('./userStatistics');
const PasswordService = require('../../../security/passwordService');
const JwtService = require('../../../security/jwtService');
const Converter = require('../../../tools/converter');
const Validity = require('../../../tools/validity');
const DateTimeUtils = require('../../../tools/dateTimeUtils');

const accessTokenExpiresIn = Converter.toSeconds(process.env.JWT_EXPIRATION_ACCESS_TOKEN);
const refreshTokenExpiresIn = Converter.toSeconds(process.env.JWT_EXPIRATION_REFRESH_TOKEN);

const jwtService = new JwtService({
  algorithm: process.env.JWT_ALGORITHM,
  accessTokenSecretKey: process.env.JWT_ACCESS_TOKEN_SECRET_KEY,
  expiresIn: accessTokenExpiresIn,
  refreshTokenSecretKey: process.env.JWT_REFRESH_TOKEN_SECRET_KEY,
  refreshExpiresIn: refreshTokenExpiresIn,
});

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class User {
  constructor({
    _id = null, // the ObjectID
    firstName = null,
    lastName = null,
    userName = null,
    email = null,
    password = null,
    roles = [UserRole.customer],
    autoVerify = false,
    newsletter = true,
    applications = [],
    application_active = null,
    verified = false,
    verification_token = null,
    companyName = '',
    addresses = [],
    license = null,
    stats = undefined,
    jwt_access_token = null,
    jwt_refresh_token = null,
    createdRefreshTokenAt = null,
    createdAt = null,
    modifiedAt = null,
    ignorePassword = false,
  } = {}) {
    this._id = _id; // the ObjectID
    this.firstName = firstName;
    this.lastName = lastName;
    this.userName = userName;
    this.email = email;
    this.password = password;
    this.roles = roles || [UserRole.customer];
    this.autoVerify = autoVerify;
    this.newsletter = newsletter;

    // The web application(s)
    this.applications = applications;
    this.application_active = application_active;

    this.verified = verified;
    // this.verified = Converter.toBoolean(options.verified); // If options.verified is undefined, set to false
    this.verification_token = verification_token;

    this.companyName = companyName;
    this.addresses = addresses;

    this.license = license;
    this.stats = stats ? new UserStatistics(stats) : new UserStatistics();

    this.jwt_access_token = jwt_access_token;
    this.jwt_refresh_token = jwt_refresh_token;
    this.createdRefreshTokenAt = createdRefreshTokenAt;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.createdAt = createdAt || nowUtc;
    this.modifiedAt = modifiedAt || nowUtc;

    const error = this.checkForError(ignorePassword);
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  static id(user) {
    if (!user._id) return '';
    return user._id.toString();
  }

  static sessionUser(user_data) {
    if (!user_data._id) return undefined;
    const user = new User({
      ...user_data,
      ignorePassword: true,
    });
    delete user.password;
    return user;
  }

  checkForError(ignorePassword = false) {
    return User.checkForError(this, ignorePassword);
  }

  static checkForError(user, ignorePassword = false) {
    if (!user || !(user instanceof User)) return new Error('invalid user details');
    if (!Validity.isValidString(user.firstName)) return new Error('invalid firstName');
    if (!Validity.isValidString(user.lastName)) return new Error('invalid lastName');
    if (!Validity.isValidString(user.userName, 6)) return new Error('invalid user name');
    if (!Validity.isValidEmail(user.email)) return new Error('invalid email');

    const error = UserStatistics.checkForError(user.stats);
    if (error) return error;

    if (user.addresses) {
      user.addresses.forEach((address) => {
        const error = Address.checkForError(address);
        if (error) return error;
      });
    }
    if (!ignorePassword) {
      if (!Validity.isValidString(user.password, 8)) return new Error('invalid password');
    }
    return null;
  }

  static get indexMap() {
    const createIndexName = (postfix) => `index_user_${postfix}`;
    const map = new Map();
    map
      .set(createIndexName('email'), {
        fieldOrSpec: { email: 1 },
        options: {
          name: createIndexName('email'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('userName'), {
        fieldOrSpec: { userName: 1 },
        options: {
          name: createIndexName('userName'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('email_applications'), {
        fieldOrSpec: { email: 1, applications: 1 },
        options: {
          name: createIndexName('email_applications'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('lastName_firstName'), {
        fieldOrSpec: { lastName: 1, firstName: 1 },
        options: {
          name: createIndexName('lastName_firstName'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('application_active'), {
        fieldOrSpec: { application_active: 1 },
        options: {
          name: createIndexName('application_active'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('country_city_postCode'), {
        fieldOrSpec: { 'addresses.country': 1, 'addresses.city': 1, 'addresses.postCode': 1 },
        options: {
          name: createIndexName('country_city_postCode'),
          sparse: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('jwt_access_token'), {
        fieldOrSpec: { jwt_access_token: 1 },
        options: {
          name: createIndexName('jwt_access_token'),
          sparse: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('verified'), {
        fieldOrSpec: { verified: 1 },
        options: {
          name: createIndexName('verified'),
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
      })
      .set(createIndexName('modifiedAt'), {
        fieldOrSpec: { modifiedAt: 1 },
        options: {
          name: createIndexName('modifiedAt'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      });

    return map;
  }

  // ============================================================================
  // Used when an access token is created and passed back during login
  static getPayloadForToken(user_data) {
    return {
      _id: User.id(user_data),
      firstName: user_data.firstName,
      application_active: user_data.application_active,
    };
  }

  // ============================================================================
  // Used when a whole user is passed back during login
  static getPayloadForSession(user_data) {
    const user = User.sessionUser(user_data);
    delete user.password;
    delete user.addresses;
    delete user.companyName;
    delete user.verification_token;
    delete user.jwt_access_token;
    delete user.jwt_refresh_token;
    delete user.createdRefreshTokenAt;
    return user;
  }

  // ============================================================================
  // Used when a whole user is passed back during login
  static findAddressIndex(user, address) {
    let error = User.checkForError(user, true);
    if (error) throw error;

    error = Address.checkForError(address);
    if (error) throw error;

    const { line1, postCode, city, country } = address;

    let index = -1;
    if (user.addresses.length > 0) {
      index = user.addresses.findIndex(address => {
        return address.line1 === line1 && address.city === city && address.postCode === postCode && address.country === country;
      });
    }

    return index;
  }

  static findAddressIndexById(user, address_id) {
    const error = User.checkForError(user, true);
    if (error) throw error;

    if (!Validity.isValidString(address_id, 1)) throw new Error('invalid address identifier');

    let index = -1;
    if (user.addresses.length > 0) {
      index = user.addresses.findIndex(address => {
        return address._id === address_id;
      });
    }

    return index;
  }

  get isCustomer() {
    return this.roles.includes(UserRole.customer);
  }

  get isEmployee() {
    return this.roles.includes(UserRole.employee);
  }

  static isAdmin(user) {
    return user && user.roles && user.roles.includes(UserRole.admin);
  }

  get requiresVerification() {
    return !(this.verified && !this.verification_token);
  }

  async checkPassword(password) {
    return await PasswordService.checkPassword(password, this.password);
  }

  async createVerifiedUserTokens() {
    if (!this.verified) return Promise.reject(new Error('unconfirmed user'));

    // If we are here, we have a user and authentication was successful.
    const payload = User.getPayloadForToken(this);
    if (!payload) return Promise.reject(new Error('cannot get user payload'));

    try {
      const accessToken = await jwtService.createAccessToken(payload);
      const refreshToken = await jwtService.createRefreshToken(payload);

      // To verify access token use:
      // const result = await jwtService.verifyAccessToken(accessToken);

      // return the tokens
      return {
        accessToken,
        refreshToken,
      };
    } catch (err) {
      return Promise.reject(err);
    }
  }
}

module.exports = User;
