const assert = require('assert');
const CreateApiClientApplicationParameters = require('../../../../../lib/models/documents/sso/requestParams/createApiClientApplicationParameters');

const API_CLIENT_ID = 'ade3b3334c4e834c4b24faf7c3fae8e2';

describe('ApiClient.checkForError throws or returns error', () => {
  it('if provided with null apiClientId', (done) => {
    assert.throws(() => {
      new CreateApiClientApplicationParameters({
        apiClientId: null
      });
    }, /invalid client identifier/);
    done();
  });

  it('if provided with null applicationName', (done) => {
    assert.throws(() => {
      new CreateApiClientApplicationParameters({
        apiClientId: API_CLIENT_ID,
        applicationName: null,
        applicationDescription: 'ccc',
        websiteUrl: 'ddd',
        returnUrl: 'eee',
      });
    }, /invalid application name/);
    done();
  });

  it('if provided with null applicationDescription', (done) => {
    assert.throws(() => {
      new CreateApiClientApplicationParameters({
        apiClientId: API_CLIENT_ID,
        applicationName: 'aaa',
        applicationDescription: null,
        websiteUrl: 'ddd',
        returnUrl: 'eee',
      });
    }, /invalid application description/);
    done();
  });

  it('if provided with null websiteUrl', (done) => {
    assert.throws(() => {
      new CreateApiClientApplicationParameters({
        apiClientId: API_CLIENT_ID,
        applicationName: 'ddd',
        applicationDescription: 'ccc',
        websiteUrl: null,
        returnUrl: 'eee',
      });
    }, /invalid website URL/);
    done();
  });

  it('if provided with null returnUrl', (done) => {
    assert.throws(() => {
      new CreateApiClientApplicationParameters({
        apiClientId: API_CLIENT_ID,
        applicationName: 'ddd',
        applicationDescription: 'ccc',
        websiteUrl: 'eee',
        returnUrl: null,
      });
    }, /invalid return URL/);
    done();
  });
});