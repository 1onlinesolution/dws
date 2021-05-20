const assert = require('assert');
const ApiClient = require('../../../../lib/models/documents/sso/apiClient');

describe('ApiClient basics', () => {
  it('Creates a basic item', (done) => {
    const apiClient = new ApiClient({
      email: 'aaa@aaa.com',
    });
    assert(typeof apiClient === 'object');
    assert(apiClient._id === null);
    assert(apiClient.email !== null);
    assert(typeof apiClient.email === 'string');
    assert(Array.isArray(apiClient.applications));
    assert(apiClient.applications.length === 0);
    assert(apiClient.createdAt instanceof Date);
    assert(apiClient.modifiedAt instanceof Date);
    done();
  });

  it('Symbol.species', (done) => {
    const apiClient = new ApiClient({
      email: 'aaa@aaa.com',
    });
    assert(apiClient instanceof ApiClient);
    done();
  });
});

describe('ApiClient.checkForError throws or returns error', () => {
  it('if provided with null email', (done) => {
    assert.throws(() => {
      new ApiClient({ email: null });
    }, /invalid email address/);
    done();
  });

  it('if provided with invalid email', (done) => {
    assert.throws(() => {
      new ApiClient({
        email: 's@@f',
      });
    }, /invalid email address/);
    done();
  });
});
