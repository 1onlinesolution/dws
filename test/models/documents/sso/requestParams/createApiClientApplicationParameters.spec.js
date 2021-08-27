const assert = require('assert');
const CreateApiClientApplicationParameters = require('../../../../../lib/models/documents/sso/requestParams/createApiClientApplicationParameters');

const API_CLIENT_ID = 'ade3b3334c4e834c4b24faf7c3fae8e2';

describe('ApiClient.checkForError throws or returns error', () => {
  it('if provided with null api_client_id', (done) => {
    assert.throws(() => {
      new CreateApiClientApplicationParameters({
        api_client_id: null
      });
    }, /invalid client identifier/);
    done();
  });

  it('if provided with null application_name', (done) => {
    assert.throws(() => {
      new CreateApiClientApplicationParameters({
        api_client_id: API_CLIENT_ID,
        application_name: null,
        application_description: 'ccc',
        websiteUrl: 'ddd',
        returnUrl: 'eee',
      });
    }, /invalid application name/);
    done();
  });

  it('if provided with null application_description', (done) => {
    assert.throws(() => {
      new CreateApiClientApplicationParameters({
        api_client_id: API_CLIENT_ID,
        application_name: 'aaa',
        application_description: null,
        websiteUrl: 'ddd',
        returnUrl: 'eee',
      });
    }, /invalid application description/);
    done();
  });

  it('if provided with null websiteUrl', (done) => {
    assert.throws(() => {
      new CreateApiClientApplicationParameters({
        api_client_id: API_CLIENT_ID,
        application_name: 'ddd',
        application_description: 'ccc',
        websiteUrl: null,
        returnUrl: 'eee',
      });
    }, /invalid website URL/);
    done();
  });

  it('if provided with null returnUrl', (done) => {
    assert.throws(() => {
      new CreateApiClientApplicationParameters({
        api_client_id: API_CLIENT_ID,
        application_name: 'ddd',
        application_description: 'ccc',
        website_url: 'eee',
        return_url: null,
      });
    }, /invalid return URL/);
    done();
  });
});