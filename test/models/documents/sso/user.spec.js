const assert = require('assert');
const User = require('../../../../lib/models/documents/sso/user');
const UserStatistics = require('../../../../lib/models/documents/sso/userStatistics');

describe('User empty', () => {
  const firstName = 'John';
  const lastName = 'Smith';
  const userName = 'jsmith';
  const email = 'a@a.com';
  const user = new User({
    firstName, lastName, email, userName, ignorePassword: true
  });

  it('Creates a basic User', (done) => {
    assert(typeof user === 'object');
    assert(user.firstName === firstName);
    assert(user.lastName === lastName);
    assert(user.userName === userName);
    assert(user.email === email);
    assert(user.autoVerify === false);
    assert(user.newsletter === true);
    assert(user.verified === false);
    assert(user.verification_token === null);
    assert(user.company_name === '');
    assert(user.license === null);

    assert(user.api_client_id === null);
    assert(user.api_client_secret === null);
    assert(user.jwt_access_token === null);
    assert(user.jwt_refresh_token === null);
    assert(user.createdRefreshTokenAt === null);

    assert(user.stats instanceof UserStatistics);
    assert(user.createdAt instanceof Date);
    assert(user.modifiedAt instanceof Date);
    done();
  });

  it('Symbol.species', (done) => {
    assert(user instanceof User);
    done();
  });
});

describe('User.checkForError throws or returns error', () => {
  it('if provided with null user', (done) => {
    const error = User.checkForError(undefined);
    assert(error !== null);
    done();
  });

  it('if not provided with firstName', (done) => {
    assert.throws(() => {
      new User({
        firstName: undefined,
        ignorePassword: true,
      });
    }, /invalid firstName/);
    done();
  });

  it('if not provided with lastName', (done) => {
    assert.throws(() => {
      new User({
        firstName: 'John',
        lastName: undefined,
        ignorePassword: true,
      });
    }, /invalid lastName/);
    done();
  });

  it('if not provided with user name', (done) => {
    assert.throws(() => {
      new User({
        firstName: 'John',
        lastName: 'Smith',
        userName: undefined,
        ignorePassword: true,
      });
    }, /invalid user name/);
    done();
  });

  it('if not provided with email', (done) => {
    assert.throws(() => {
      new User({
        firstName: 'John',
        lastName: 'Smith',
        userName: 'lalala',
        email: undefined,
        ignorePassword: true,
      });
    }, /invalid email/);
    done();
  });

  it('if not provided with userName', (done) => {
    assert.throws(() => {
      new User({
        firstName: 'John',
        lastName: 'Smith',
        email: 'a@a.com',
        userName: undefined,
        ignorePassword: true,
      });
    }, /invalid user name/);
    done();
  });
});
