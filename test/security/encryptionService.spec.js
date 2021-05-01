const assert = require('assert');
const EncryptionService = require('../../lib/security/encryptionService');

describe('EncryptionService', () => {
  const encryptionService = new EncryptionService({ encryptionKey: process.env.ENCRYPTION_KEY });
  const message = 'I love Greece and my family';

  before(async () => {
    // runs before all tests in this block
  });

  after(() => {
    // runs after all tests in this block
  });

  beforeEach(() => {
    // runs before each test in this block
  });

  afterEach(() => {
    // runs after each test in this block
  });

  it('createIV() creates vector', async () => {
    const vector = await encryptionService.createIV();
    assert(vector && vector.length > 0);
  });

  it('encrypt/decrypt() work fine', async () => {
    const { iv, encrypted } = await encryptionService.encrypt(message);
    // console.log(`ivPart        = ${iv}`);
    // console.log(`encryptedPart = ${encrypted}`);
    const result = await encryptionService.decrypt(iv, encrypted);
    assert(result === message);
  });

  it('encryptCompact/decryptCompact() work fine', async () => {
    const secret = await encryptionService.encryptCompact(message);
    const result = await encryptionService.decryptCompact(secret);
    assert(result === message);
  });

  it('encryptObjectCompact(/decryptCompact() work fine', async () => {
    const data = { item: message };
    const secret = await encryptionService.encryptObjectCompact(data);
    const result = await encryptionService.decryptObjectCompact(secret);
    const { item } = result;
    assert(item === message);
  });

  it('Ctor throws if encryption key not provided', (done) => {
    assert.throws(() => {
      new EncryptionService({});
    }, /Encryption key is missing/);
    done();
  });
});
