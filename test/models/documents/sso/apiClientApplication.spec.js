const assert = require('assert');
const ApiClientApplication = require('../../../../lib/models/documents/sso/apiClientApplication');

const APICLIENTID = 'ade3b3334c4e834c4b24faf7c3fae8e2';

describe('ApiClientApplication basic', () => {
  it('Creates an empty ApiClientApplication item', (done) => {
    const app = new ApiClientApplication({
      api_client_id: APICLIENTID,
      application_name: 'aaa',
      application_description: 'bbb',
      website_url: 'ccc',
      return_url: 'ddd',
    });

    assert(typeof app === 'object');
    assert(app.api_client_id === APICLIENTID);
    assert(app.application_name === 'aaa');
    assert(app.application_description === 'bbb');
    assert(app.website_url === 'ccc');
    assert(app.return_url === 'ddd');
    assert(app.created_at instanceof Date);
    assert(app.modified_at instanceof Date);
    assert(app.authorization_code === null);
    assert(app.authorizationCodeExpirationDate === null);
    assert(app.accessToken === null);
    assert(app.refreshToken === null);
    assert(app.accessTokenExpiresIn === 360);
    assert(app.refreshTokenExpiresIn === 3600);

    done();
  });

  it('Symbol.species', (done) => {
    const app = new ApiClientApplication({
      api_client_id: APICLIENTID,
      application_name: 'aaa',
      application_description: 'bbb',
      website_url: 'ccc',
      return_url: 'ddd',
    });

    assert(app instanceof ApiClientApplication);
    done();
  });

  it('gives a payload an authorization code', (done) => {
    const app = new ApiClientApplication({
      api_client_id: APICLIENTID,
      application_name: 'aaa',
      application_description: 'bbb',
      website_url: 'ccc',
      return_url: 'ddd',
    });

    const payload = app.getPayload();
    assert(typeof payload === 'object');
    assert(payload.application_name === app.application_name);
    done();
  });

  it('creates tokens', async () => {
    const app = new ApiClientApplication({
      api_client_id: APICLIENTID,
      application_name: 'aaa',
      application_description: 'bbb',
      website_url: 'ccc',
      return_url: 'ddd',
    });

    const result = await app.createTokens();
    // console.log(`result = ${JSON.stringify(result)}`);
    assert(typeof result === 'object');
    assert(result.accessToken !== '');
    assert(result.refreshToken !== '');
    assert(result.accessTokenExpiresIn > 0);
    assert(result.refreshTokenExpiresIn > 0);
  });
});

describe('ApiClientApplication.checkPassword throws or returns error', () => {
  it('if provided with invalid object', (done) => {
    const error = ApiClientApplication.checkForError(undefined);
    assert(error !== null);
    done();
  });

  it('if provided with invalid app client id', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        api_client_id: undefined,
      });
    }, /invalid client identifier/);
    done();
  });

  it('if provided with invalid app name', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        api_client_id: APICLIENTID,
        application_name: undefined,
        application_description: 'bbb',
        website_url: 'ccc',
        return_url: 'ddd',
      });
    }, /invalid application name/);
    done();
  });

  it('if provided with invalid app description', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        api_client_id: APICLIENTID,
        application_name: 'aaa',
        application_description: undefined,
        website_url: 'ccc',
        return_url: 'ddd',
      });
    }, /invalid application description/);
    done();
  });

  it('if provided with invalid website url', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        api_client_id: APICLIENTID,
        application_name: 'aaa',
        application_description: 'bbb',
        website_url: undefined,
        return_url: 'ddd',
      });
    }, /invalid website URL/);
    done();
  });

  it('if provided with invalid return url', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        api_client_id: APICLIENTID,
        application_name: 'aaa',
        application_description: 'bbb',
        website_url: 'ccc',
        return_url: undefined,
      });
    }, /invalid return URL/);
    done();
  });
});

describe('ApiClientApplication.generateAuthorizationCode', () => {
  it('generates an authorization code', async () => {
    const app = new ApiClientApplication({
      api_client_id: APICLIENTID,
      application_name: 'aaa',
      application_description: 'bbb',
      website_url: 'ccc',
      return_url: 'ddd',
      clientId: 'eee',
      clientSecret: 'fff',
    });

    const result = await ApiClientApplication.generateAuthorizationCode(app);
    assert(result instanceof ApiClientApplication);
    assert(result.authorization_code !== '');
    assert(result.authorizationCodeExpirationDate instanceof Date);
  });

  it('throws if provided with invalid app', async () => {
    try {
      await ApiClientApplication.generateAuthorizationCode(null);
    } catch (err) {
      assert(err.name === 'Error');
      assert(err.message === 'invalid API client details');
    }
  });
});

describe('ApiClientApplication.createTokens', () => {
  it('creates tokens', async () => {
    const app = new ApiClientApplication({
      api_client_id: APICLIENTID,
      application_name: 'aaa',
      application_description: 'bbb',
      website_url: 'ccc',
      return_url: 'ddd',
      clientId: 'eee',
      clientSecret: 'fff',
    });

    const result = await ApiClientApplication.generateAuthorizationCode(app);
    assert(result instanceof ApiClientApplication);
    assert(result.authorization_code !== '');
    assert(result.authorizationCodeExpirationDate instanceof Date);
  });

  it('throws if provided with invalid app', async () => {
    try {
      await ApiClientApplication.generateAuthorizationCode(null);
    } catch (err) {
      assert(err.name === 'Error');
      assert(err.message === 'invalid API client details');
    }
  });
});
