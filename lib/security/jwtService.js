// https://jwt.io/
// https://auth0.com/docs/security/store-tokens

const jwt = require('jsonwebtoken');

class JwtService {
  constructor({
    expiresIn = undefined,
    algorithm = undefined,
    accessTokenSecretKey = undefined,
    refreshTokenSecretKey = undefined,
    refreshExpiresIn = undefined,
  }) {
    this.accessTokenSecretKey = accessTokenSecretKey;
    this.refreshTokenSecretKey = refreshTokenSecretKey;
    this.defaultAccessJwtOptions = {
      expiresIn: expiresIn,
      algorithm: algorithm,
    };

    this.defaultRefreshJwtOptions = {
      expiresIn: refreshExpiresIn || '60m',
      algorithm: algorithm,
    };
  }

  sign(payload, isAccessToken = true) {
    const options = isAccessToken ? this.defaultAccessJwtOptions : this.defaultRefreshJwtOptions;
    const secret = isAccessToken ? this.accessTokenSecretKey : this.refreshTokenSecretKey;

    return new Promise((resolve, reject) => {
      jwt.sign(payload, secret, options, (err, token) => {
        if (err) {
          // For any error detected
          reject(err);
        } else {
          // When task is finished
          resolve(token);
        }
      });
    });
  }

  async createAccessToken(payload) {
    return await this.sign(payload, true);
  }

  async createRefreshToken(payload) {
    return await this.sign(payload, false);
  }

  verifyAccessToken(token) {
    const secret = this.accessTokenSecretKey;
    const options = this.defaultAccessJwtOptions;
    return new Promise((resolve, reject) => {
      jwt.verify(token, secret, options, (err, payload) => {
        if (err) {
          // For any error detected
          return reject(err);
        }

        // When task is finished
        return resolve(payload);
      });
    });
  }

  verifyRefreshToken(token) {
    const secret = this.refreshTokenSecretKey;
    const options = this.defaultRefreshJwtOptions;
    return new Promise((resolve, reject) => {
      jwt.verify(token, secret, options, (err, payload) => {
        if (err) {
          // For any error detected
          return reject(err);
        }

        // When task is finished
        return resolve(payload);
      });
    });
  }

  async ensureToken(headers) {
    const token = this.extractTokenFromHeader(headers);
    try {
      // returns the payload
      return await this.verifyAccessToken(token);
    } catch (err) {
      console.log(err);
      return null;
    }
  }

  extractTokenFromHeader(headers) {
    const bearerHeader = headers.authorization;
    if (!bearerHeader) return null;
    return bearerHeader.split(' ')[1];
  }
}

module.exports = JwtService;
