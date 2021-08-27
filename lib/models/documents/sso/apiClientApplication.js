const { Converter, Validity, DateTimeUtils } = require('@1onlinesolution/dws-utils');
const { PasswordService, JwtService } = require('@1onlinesolution/dws-crypto');
const User = require('./user');

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
    api_client_id,
    application_name,
    application_description,
    website_url,
    return_url,
    _id = null,
    created_at = null,
    modified_at = null,
    authorization_code = null,
    authorizationCodeExpirationDate = null,
    access_token = null,
    refresh_token = null,
  } = {}) {
    this._id = _id; // the ObjectID
    this.api_client_id = api_client_id;
    this.application_name = application_name;
    this.application_description = application_description;
    this.website_url = website_url;
    this.return_url = return_url;

    // The following is requested per login operation
    // Once the client has the code, can exchange it for access tokens
    this.authorization_code = authorization_code;
    this.authorizationCodeExpirationDate = authorizationCodeExpirationDate;

    this.access_token = access_token;
    this.refresh_token = refresh_token;
    this.accessTokenExpiresIn = accessTokenExpiresIn;
    this.refreshTokenExpiresIn = refreshTokenExpiresIn;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.created_at = created_at || nowUtc;
    this.modified_at = modified_at || nowUtc;

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
      api_client_id: this.api_client_id,
      application_name: this.application_name,
      website_url: this.website_url,
      return_url: this.return_url,
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
    if (!Validity.isValidString(apiClientApplication.api_client_id, sizeClientId)) return new Error('invalid client identifier');
    if (!Validity.isValidString(apiClientApplication.application_name)) return new Error('invalid application name');
    if (!Validity.isValidString(apiClientApplication.application_description)) return new Error('invalid application description');
    if (!Validity.isValidString(apiClientApplication.website_url)) return new Error('invalid website URL');
    if (!Validity.isValidString(apiClientApplication.return_url)) return new Error('invalid return URL');
    return null;
  }

  static get indexMap() {
    const createIndexName = (postfix) => `index_apiClientApplication_${postfix}`;
    const map = new Map();
    map
      .set(createIndexName('apiClientId_applicationName_websiteUrl'), {
        fieldOrSpec: { api_client_id: 1, application_name: 1, website_url: 1 },
        options: {
          name: createIndexName('apiClientId_applicationName_websiteUrl'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('applicationName_websiteUrl'), {
        fieldOrSpec: { application_name: 1, website_url: 1 },
        options: {
          name: createIndexName('applicationName_websiteUrl'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('authorization_code'), {
        fieldOrSpec: { authorization_code: 1 },
        options: {
          name: createIndexName('authorization_code'),
          partialFilterExpression: { authorization_code: { $exists: true } },
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('refresh_token'), {
        fieldOrSpec: { refresh_token: 1 },
        options: {
          name: createIndexName('refresh_token'),
          partialFilterExpression: { refresh_token: { $exists: true } },
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('created_at'), {
        fieldOrSpec: { created_at: 1 },
        options: {
          name: createIndexName('created_at'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('modified_at'), {
        fieldOrSpec: { modified_at: 1 },
        options: {
          name: createIndexName('modified_at'),
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
      apiClientApplication.authorization_code = await PasswordService.randomBytesAsToken(
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
      const access_token = await jwtService.createAccessToken(payload);
      const refresh_token = await jwtService.createRefreshToken(payload);

      // To verify access token use:
      // const result = await jwtService.verifyAccessToken(access_token);

      // return the tokens
      return {
        access_token,
        refresh_token,
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
      const access_token = await jwtService.createAccessToken(payload);

      // To verify access token use:
      // const result = await jwtService.verifyAccessToken(access_token);

      // return the tokens
      return {
        access_token: access_token,
        expires_in: accessTokenExpiresIn,
      };
    } catch (err) {
      return Promise.reject(err);
    }
  }
}

module.exports = ApiClientApplication;
