const bcrypt = require('bcrypt');
const crypto = require('crypto');

const DEFAULT_SALT_ROUNDS = 12.5;

class PasswordService {
  static async generateSalt(rounds = undefined) {
    if (!rounds) {
      return bcrypt.genSalt(PasswordService.GetDefaultSaltRounds());
    }

    return bcrypt.genSalt(rounds);
  }

  static async checkPassword(myPlaintextPassword, hashedPassword) {
    // https://www.npmjs.com/package/bcrypt

    if (!myPlaintextPassword) {
      return Promise.reject(new Error('invalid password'));
    }

    if (!hashedPassword) {
      return Promise.reject(new Error('invalid hashed password'));
    }

    return await bcrypt.compare(myPlaintextPassword, hashedPassword);
  }

  static async hashPassword(password) {
    if (!password) {
      return Promise.reject(new Error('invalid password'));
    }

    return await bcrypt.hash(password, DEFAULT_SALT_ROUNDS);
  }

  static async randomBytes(length = 32) {
    if (length <= 0) return Promise.reject(new Error('invalid length'));
    return crypto.randomBytes(length);
  }

  static async randomBytesAsToken(length = 32, encoding = 'hex') {
    const buffer = await this.randomBytes(length);
    if(!buffer) return Promise.reject(new Error('cannot generate token buffer'));
    return buffer.toString(encoding);
  }

  static GetDefaultSaltRounds() {
    return DEFAULT_SALT_ROUNDS;
  }
}

module.exports = PasswordService;
