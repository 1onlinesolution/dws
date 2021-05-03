const Validity = require('../../../tools/validity');
const CreateApiClientApplicationParameters = require('./requestParams/createApiClientApplicationParameters');
const EncryptionService = require('../../../security/encryptionService');
const PasswordService = require('../../../security/passwordService');
const JwtService = require('../../../security/jwtService');
const Converter = require('../../../tools/converter');
const DateTimeUtils = require('../../../tools/dateTimeUtils');

const accessTokenExpiresIn = Converter.toSeconds(process.env.JWT_EXPIRATION_ACCESS_TOKEN);
const refreshTokenExpiresIn = Converter.toSeconds(process.env.JWT_EXPIRATION_REFRESH_TOKEN);
// console.log(`accessTokenExpiresIn = ${accessTokenExpiresIn}`);
// console.log(`refreshTokenExpiresIn = ${refreshTokenExpiresIn}`);

const encryptionService = new EncryptionService({
  encryptionKey: process.env.ENCRYPTION_KEY,
});

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
    applicationName,
    applicationDescription,
    websiteUrl,
    returnUrl,
    clientId,
    clientSecret,
    createdAt,
    modifiedAt,
    authorizationCode = null,
    authorizationCodeExpirationDate = null,
  } = {}) {
    this.applicationName = applicationName;
    this.applicationDescription = applicationDescription;
    this.websiteUrl = websiteUrl;
    this.returnUrl = returnUrl;
    this.clientId = clientId;
    this.clientSecret = clientSecret;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.createdAt = createdAt || nowUtc;
    this.modifiedAt = modifiedAt || nowUtc;

    // The following is requested per login operation
    // Once the client has the code, can exchange it for access tokens
    this.authorizationCode = authorizationCode;
    this.authorizationCodeExpirationDate = authorizationCodeExpirationDate;

    this.accessToken = null;
    this.refreshToken = null;
    this.expiresIn = null;

    const error = this.checkForError();
    if (error) throw error;
    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  getPayload() {
    return {
      applicationName: this.applicationName,
    };
  };

  checkForError() {
    return ApiClientApplication.checkForError(this);
  }

  static checkForError(apiClientApplication) {
    if (!apiClientApplication || !(apiClientApplication instanceof ApiClientApplication)) {
      return new Error('invalid API client details');
    }
    if (!Validity.isValidString(apiClientApplication.applicationName)) return new Error('invalid application name');
    if (!Validity.isValidString(apiClientApplication.applicationDescription)) return new Error('invalid application description');
    if (!Validity.isValidString(apiClientApplication.websiteUrl)) return new Error('invalid website URL');
    if (!Validity.isValidString(apiClientApplication.returnUrl)) return new Error('invalid return URL');
    if (!Validity.isValidString(apiClientApplication.clientId)) return new Error('invalid client identifier');
    if (!Validity.isValidString(apiClientApplication.clientSecret)) return new Error('invalid client secret');
    return null;
  }

  static async createApiClientApplication(createApiClientApplicationParameters) {
    const error = CreateApiClientApplicationParameters.checkForError(createApiClientApplicationParameters);
    if (error) return Promise.reject(error);

    // const afterOneMonthUtc = DateTimeUtils.currentUtcDate();
    // const oneHourInMilSec = 60 * 60 * 1000;
    // const oneMonthInMilSec = 30 * 24 * oneHourInMilSec;
    // afterOneMonthUtc.setTime(afterOneMonthUtc.getTime() + oneMonthInMilSec);

    try {
      const clientId = await PasswordService.randomBytesAsToken(16, 'hex');
      const token = await encryptionService.encryptObjectCompact({
        email: createApiClientApplicationParameters.email,
        clientId: clientId,
        creationDate: DateTimeUtils.currentUtcDate(),
      });

      return new ApiClientApplication({
        clientId: clientId,
        clientSecret: token,
        ...createApiClientApplicationParameters,
      });
    } catch (err) {
      return Promise.reject(err);
    }
  }

  static async generateAuthorizationCode(apiClientApplication) {
    const error = ApiClientApplication.checkForError(apiClientApplication);
    if (error) return Promise.reject(error);

    const expiresAfterOneHourInMilSec = DateTimeUtils.currentUtcDate();
    const oneHourInMilSec = 60 * 60 * 1000;
    expiresAfterOneHourInMilSec.setTime(expiresAfterOneHourInMilSec.getTime() + oneHourInMilSec);

    try {
      apiClientApplication.authorizationCode = await PasswordService.randomBytesAsToken(16, 'hex');
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
        expiresIn: accessTokenExpiresIn,
      };
    } catch (err) {
      return Promise.reject(err);
    }
  }
}

module.exports = ApiClientApplication;
