const assert = require('assert');
const UserLogin = require('../../../../lib/models/documents/sso/userLogin');

describe('UserLogin empty', () => {
  const ip = '::1';
  const email = 'a@a.com';
  const userLogin = new UserLogin({ ip, email});

  it('Creates a basic UserLogin', (done) => {
    assert(typeof userLogin === 'object');
    assert(userLogin.ip !== null);
    assert(userLogin.email !== null);

    assert(userLogin.ip !== '');
    assert(userLogin.email !== '');

    assert(userLogin._id === null);
    assert(userLogin.createdAt !== null);
    done();
  });

  it('Symbol.species', (done) => {
    assert(userLogin instanceof UserLogin);
    done();
  });
});

describe('UserLogin.checkForError throws or returns error', () => {
  it('if provided with null userLogin', (done) => {
    const error = UserLogin.checkForError(undefined);
    assert(error !== null);
    done();
  });

  it('if not provided with ip', (done) => {
    assert.throws(() => {
      const ip = null;
      const email = 'a@a.com';
      new UserLogin({ ip, email });
    }, /invalid IP address/);
    done();
  });

  it('if not provided with email', (done) => {
    assert.throws(() => {
      const ip = '::1';
      const email = null;
      new UserLogin({ ip, email });
    }, /invalid user email address/);
    done();
  });
});
