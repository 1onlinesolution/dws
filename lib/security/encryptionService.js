const crypto = require('crypto');
const PasswordService = require('./passwordService');

// https://nodejs.org/dist/latest-v10.x/docs/api/crypto.html#crypto_crypto_createcipheriv_algorithm_key_iv_options
// https://nodejs.org/dist/latest-v10.x/docs/api/crypto.html#crypto_crypto_createdecipheriv_algorithm_key_iv_options

// Initialization vectors should be unpredictable and unique; ideally, they will be cryptographically random.
// They do not have to be secret: IVs are typically just added to ciphertext messages unencrypted.
// It may sound contradictory that something has to be unpredictable and unique, but does not have to be secret;
// it is important to remember that an attacker must not be able to predict ahead of time what a given IV will be.
const IV_LENGTH = 16; // For AES, this is always 16

class EncryptionService {
  constructor({ algorithm = 'aes-256-cbc', encryptionKey = undefined }) {
    this.algorithm = algorithm || 'aes-256-cbc';

    //
    // The key is the raw key used by the algorithm and iv is an initialization vector.
    // Both arguments must be 'utf8' encoded strings, Buffers, TypedArray, or DataViews.
    // If the cipher does not need an initialization vector, iv may be null.
    //
    // Example key: 6b42ea8281fb0056b868e1614a1dfe58c47d74536e979af8b193828050db5d31
    //
    if (!encryptionKey) {
      throw new Error('Encryption key is missing');
    }

    this.encryptionKey = encryptionKey;
    this.key = Buffer.from(encryptionKey, 'hex');

    // Initialization vectors should be unpredictable and unique; ideally, they will be cryptographically random.
    // They do not have to be secret: IVs are typically just added to ciphertext messages unencrypted.
    // It may sound contradictory that something has to be unpredictable and unique, but does not have to be secret;
    // it is important to remember that an attacker must not be able to predict ahead of time what a given IV will be.
    this.iv_length = IV_LENGTH;
  }

  async createIV() {
    // https://stackoverflow.com/a/49021891
    // All IVs/nonces should be generated randomly. Always.
    // The important thing to keep in mind here is that an IV is not a secret.
    // You can pass it publicly.
    return await PasswordService.randomBytes(this.iv_length);
  }

  async encrypt(text, encoding = 'hex') {
    try {
      const iv = await this.createIV();
      const cipher = crypto.createCipheriv(this.algorithm, this.key, iv, undefined);

      // input_encoding:  'utf8' | 'ascii' | 'binary'
      // output_encoding: 'binary' | 'base64' | 'hex'
      let encrypted = cipher.update(text, 'utf8', encoding);
      encrypted += cipher.final(encoding);
      return {
        iv: iv.toString(encoding),
        encrypted: encrypted.toString(encoding),
      };
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async encryptObject(object, encoding = 'hex') {
    try {
      return await this.encrypt(JSON.stringify(object), encoding);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async encryptCompact(text, encoding = 'hex') {
    try {
      const result = await this.encrypt(text, encoding);
      return `${result.iv}:${result.encrypted}`;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async encryptObjectCompact(object, encoding = 'hex') {
    try {
      const result = await this.encryptObject(object, encoding);
      return `${result.iv}:${result.encrypted}`;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  decrypt(iv, encrypted, encoding = 'hex') {
    const ivBuffer = Buffer.from(iv, encoding);
    const encryptedText = Buffer.from(encrypted, encoding);
    const decipher = crypto.createDecipheriv(this.algorithm, this.key, ivBuffer);
    let decrypted = decipher.update(encryptedText, encoding);
    decrypted += decipher.final();

    return decrypted.toString();
  }

  decryptCompact(text, encoding = 'hex') {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), encoding);
    const encryptedText = Buffer.from(textParts.join(':'), encoding);
    const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
    let decrypted = decipher.update(encryptedText, encoding);
    decrypted += decipher.final();

    return decrypted.toString();
  }

  decryptObjectCompact(encryptedText, encoding = 'hex') {
    const decrypted = this.decryptCompact(encryptedText, encoding);
    return JSON.parse(decrypted);
  }
}

module.exports = EncryptionService;
