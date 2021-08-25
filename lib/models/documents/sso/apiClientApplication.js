const User = require('./user');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');
const DateTimeUtils = require('@1onlinesolution/dws-utils/lib/dateTimeUtils');
const Converter = require('@1onlinesolution/dws-utils/lib/converter');
const { PasswordService, JwtService } = require('@1onlinesolution/dws-crypto');

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
class ApiClientApplication {
  constructor({
    apiClientId,
    applicationName,
    applicationDescription,
    websiteUrl,
    returnUrl,
    _id = null,
    createdAt = null,
    modifiedAt = null,
    authorizationCode = null,
    authorizationCodeExpirationDate = null,
    accessToken = null,
    refreshToken = null,
  } = {}) {
    this._id = _id; // the ObjectID
    this.apiClientId = apiClientId;
    this.applicationName = applicationName;
    this.applicationDescription = applicationDescription;
    this.websiteUrl = websiteUrl;
    this.returnUrl = returnUrl;

    // The following is requested per login operation
    // Once the client has the code, can exchange it for access tokens
    this.authorizationCode = authorizationCode;
    this.authorizationCodeExpirationDate = authorizationCodeExpirationDate;

    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.accessTokenExpiresIn = accessTokenExpiresIn;
    this.refreshTokenExpiresIn = refreshTokenExpiresIn;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.createdAt = createdAt || nowUtc;
    this.modifiedAt = modifiedAt || nowUtc;

    const error = this.checkForError();
    if (error) throw error;
    return this;
  }

  static get clientIdLength() {
    return 16;
  }

  static get [Symbol.species]() {
    return this;
  }

  getPayload() {
    return {
      apiClientId: this.apiClientId,
      applicationName: this.applicationName,
      websiteUrl: this.websiteUrl,
      returnUrl: this.returnUrl,
    };
  };

  checkForError() {
    return ApiClientApplication.checkForError(this);
  }

  static checkForError(apiClientApplication) {
    if (!apiClientApplication || !(apiClientApplication instanceof ApiClientApplication)) {
      return new Error('invalid API client details');
    }

    const sizeClientId = User.clientIdLength * 2;
    if (!Validity.isValidString(apiClientApplication.apiClientId, sizeClientId)) return new Error('invalid client identifier');
    if (!Validity.isValidString(apiClientApplication.applicationName)) return new Error('invalid application name');
    if (!Validity.isValidString(apiClientApplication.applicationDescription)) return new Error('invalid application description');
    if (!Validity.isValidString(apiClientApplication.websiteUrl)) return new Error('invalid website URL');
    if (!Validity.isValidString(apiClientApplication.returnUrl)) return new Error('invalid return URL');
    return null;
  }

  static get indexMap() {
    const createIndexName = (postfix) => `index_apiClientApplication_${postfix}`;
    const map = new Map();
    map
      .set(createIndexName('apiClientId_applicationName_websiteUrl'), {
        fieldOrSpec: { apiClientId: 1, applicationName: 1, websiteUrl: 1 },
        options: {
          name: createIndexName('apiClientId_applicationName_websiteUrl'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('applicationName_websiteUrl'), {
        fieldOrSpec: { applicationName: 1, websiteUrl: 1 },
        options: {
          name: createIndexName('applicationName_websiteUrl'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('authorizationCode'), {
        fieldOrSpec: { authorizationCode: 1 },
        options: {
          name: createIndexName('authorizationCode'),
          partialFilterExpression: { authorizationCode: { $exists: true } },
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('refreshToken'), {
        fieldOrSpec: { refreshToken: 1 },
        options: {
          name: createIndexName('refreshToken'),
          partialFilterExpression: { refreshToken: { $exists: true } },
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

  static get authorizationCodeLength() {
    return 16;
  }

  static async generateAuthorizationCode(apiClientApplication) {
    const error = ApiClientApplication.checkForError(apiClientApplication);
    if (error) return Promise.reject(error);

    const expiresAfterOneHourInMilSec = DateTimeUtils.currentUtcDate();
    const oneHourInMilSec = 60 * 60 * 1000;
    expiresAfterOneHourInMilSec.setTime(expiresAfterOneHourInMilSec.getTime() + oneHourInMilSec);

    try {
      apiClientApplication.authorizationCode = await PasswordService.randomBytesAsToken(
        ApiClientApplication.authorizationCodeLength,
        'hex');
      apiClientApplication.authorizationCodeExpirationDate = expiresAfterOneHourInMilSec;
      return apiClientApplication;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async createTokens() {
    // If we are here, we have a user and authentication was successful.
    const payload = this.getPayload();
    if (!payload) return Promise.reject(new Error('cannot get payload'));

    try {
      const accessToken = await jwtService.createAccessToken(payload);
      const refreshToken = await jwtService.createRefreshToken(payload);

      // To verify access token use:
      // const result = await jwtService.verifyAccessToken(accessToken);

      // return the tokens
      return {
        accessToken,
        refreshToken,
        accessTokenExpiresIn: accessTokenExpiresIn,
        refreshTokenExpiresIn: refreshTokenExpiresIn,
      };
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async createAccessToken() {
    // If we are here, we have a user and authentication was successful.
    const payload = this.getPayload();
    if (!payload) return Promise.reject(new Error('cannot get payload'));

    try {
      const accessToken = await jwtService.createAccessToken(payload);

      // To verify access token use:
      // const result = await jwtService.verifyAccessToken(accessToken);

      // return the tokens
      return {
        accessToken: accessToken,
        accessTokenExpiresIn: accessTokenExpiresIn,
      };
    } catch (err) {
      return Promise.reject(err);
    }
  }
}

module.exports = ApiClientApplication;
