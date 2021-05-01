const assert = require('assert');
const PasswordService = require('../../lib/security/passwordService');

// https://nodejs.org/api/assert.html#assert_assert_throws_block_error_message

// https://stackoverflow.com/a/26572442

describe('PasswordService.checkPassword throws', () => {
  it('if not provided with a password', async () => {
    await assert.rejects(
      async () => {
        return PasswordService.checkPassword(undefined, 'dummy');
      },
      {
        name: 'Error',
        message: 'invalid password',
      },
    );
  });

  it('if not provided with a hashed password', async () => {
    await assert.rejects(
      async () => {
        return PasswordService.checkPassword('dummy', undefined);
      },
      {
        name: 'Error',
        message: 'invalid hashed password',
      },
    );
  });
});

describe('PasswordService', () => {
  const password = 'ellada is the best place to live';

  let salt = '';
  let hash = '';

  before(async () => {
    // runs before all tests in this block
    salt = await PasswordService.generateSalt();
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

  it('generateSalt() generates salt', async () => {
    const salt = await PasswordService.generateSalt();
    assert(salt && salt.length > 0);
  });

  it('hashPassword() successfully creates hashed password', async () => {
    // const result = await PasswordService.hashPassword(password);
    // return PasswordService.hashPassword(password)
    //   .then(result => {
    //     assert(result.hash && result.hash.length > 0);
    //     assert(result.salt && result.salt.length > 0);
    //   });
    hash = await PasswordService.hashPassword(password);
    assert(hash && hash.length > 0);
  });

  it('checkPassword() confirms password', async () => {
    const result = await PasswordService.checkPassword(password, hash);
    assert(result);
  });

  it('randomBytes() returns bytes', async () => {
    const bytes = await PasswordService.randomBytes();
    assert(bytes && bytes.length > 0);
  });

  it('randomBytesAsToken() returns bytes', async () => {
    const bytes = await PasswordService.randomBytesAsToken();
    assert(bytes && bytes.length > 0);
  });

  it('randomBytes throws if not provided with positive size', async () => {
    try {
      await PasswordService.randomBytes(-1);
    } catch (err) {
      assert(err.name === 'Error');
      assert(err.message === 'invalid length');
    }
  });

  it('randomBytesAsToken throws if not provided with positive size', async () => {
    try {
      await PasswordService.randomBytesAsToken(-1);
    } catch (err) {
      assert(err.name === 'Error');
      assert(err.message === 'invalid length');
    }
  });

  it('hashPassword throws if not provided with password', async () => {
    try {
      await PasswordService.hashPassword();
    } catch (err) {
      assert(err.name === 'Error');
      assert(err.message === 'invalid password');
    }
  });
});
