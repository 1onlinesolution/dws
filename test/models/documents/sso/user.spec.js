const assert = require('assert');
const User = require('../../../../lib/models/documents/sso/user');
const UserStatistics = require('../../../../lib/models/documents/sso/userStatistics');

describe('User empty', () => {
  const first_name = 'John';
  const last_name = 'Smith';
  const user_name = 'jsmith';
  const email = 'a@a.com';
  const user = new User({
    first_name, last_name, email, user_name, ignore_password: true
  });

  it('Creates a basic User', (done) => {
    assert(typeof user === 'object');
    assert(user.first_name === first_name);
    assert(user.last_name === last_name);
    assert(user.user_name === user_name);
    assert(user.email === email);
    assert(user.auto_verify === false);
    assert(user.newsletter === true);
    assert(user.verified === false);
    assert(user.verification_token === null);
    assert(user.company_name === '');
    assert(user.license === null);

    assert(user.api_client_id === null);
    assert(user.api_client_secret === null);
    assert(user.jwt_access_token === null);
    assert(user.jwt_refresh_token === null);
    assert(user.refresh_token_created_at === null);

    assert(user.stats instanceof UserStatistics);
    assert(user.created_at instanceof Date);
    assert(user.modified_at instanceof Date);
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

  it('if not provided with first_name', (done) => {
    assert.throws(() => {
      new User({
        first_name: undefined,
        ignore_password: true,
      });
    }, /invalid first_name/);
    done();
  });

  it('if not provided with last_name', (done) => {
    assert.throws(() => {
      new User({
        first_name: 'John',
        last_name: undefined,
        ignore_password: true,
      });
    }, /invalid last_name/);
    done();
  });

  it('if not provided with user name', (done) => {
    assert.throws(() => {
      new User({
        first_name: 'John',
        last_name: 'Smith',
        user_name: undefined,
        ignore_password: true,
      });
    }, /invalid user name/);
    done();
  });

  it('if not provided with email', (done) => {
    assert.throws(() => {
      new User({
        first_name: 'John',
        last_name: 'Smith',
        user_name: 'lalala',
        email: undefined,
        ignore_password: true,
      });
    }, /invalid email/);
    done();
  });

  it('if not provided with user_name', (done) => {
    assert.throws(() => {
      new User({
        first_name: 'John',
        last_name: 'Smith',
        email: 'a@a.com',
        user_name: undefined,
        ignore_password: true,
      });
    }, /invalid user name/);
    done();
  });
});
