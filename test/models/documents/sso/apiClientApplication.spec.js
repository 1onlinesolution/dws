const assert = require('assert');
const ApiClientApplication = require('../../../../lib/models/documents/sso/apiClientApplication');

const APICLIENTID = 'ade3b3334c4e834c4b24faf7c3fae8e2';

describe('ApiClientApplication basic', () => {
  it('Creates an empty ApiClientApplication item', (done) => {
    const app = new ApiClientApplication({
      apiClientId: APICLIENTID,
      applicationName: 'aaa',
      applicationDescription: 'bbb',
      websiteUrl: 'ccc',
      returnUrl: 'ddd',
    });

    assert(typeof app === 'object');
    assert(app.apiClientId === APICLIENTID);
    assert(app.applicationName === 'aaa');
    assert(app.applicationDescription === 'bbb');
    assert(app.websiteUrl === 'ccc');
    assert(app.returnUrl === 'ddd');
    assert(app.createdAt instanceof Date);
    assert(app.modifiedAt instanceof Date);
    assert(app.authorizationCode === null);
    assert(app.authorizationCodeExpirationDate === null);
    assert(app.accessToken === null);
    assert(app.refreshToken === null);
    assert(app.accessTokenExpiresIn === 360);
    assert(app.refreshTokenExpiresIn === 3600);

    done();
  });

  it('Symbol.species', (done) => {
    const app = new ApiClientApplication({
      apiClientId: APICLIENTID,
      applicationName: 'aaa',
      applicationDescription: 'bbb',
      websiteUrl: 'ccc',
      returnUrl: 'ddd',
    });

    assert(app instanceof ApiClientApplication);
    done();
  });

  it('gives a payload an authorization code', (done) => {
    const app = new ApiClientApplication({
      apiClientId: APICLIENTID,
      applicationName: 'aaa',
      applicationDescription: 'bbb',
      websiteUrl: 'ccc',
      returnUrl: 'ddd',
    });

    const payload = app.getPayload();
    assert(typeof payload === 'object');
    assert(payload.applicationName === app.applicationName);
    done();
  });

  it('creates tokens', async () => {
    const app = new ApiClientApplication({
      apiClientId: APICLIENTID,
      applicationName: 'aaa',
      applicationDescription: 'bbb',
      websiteUrl: 'ccc',
      returnUrl: 'ddd',
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
        apiClientId: undefined,
      });
    }, /invalid client identifier/);
    done();
  });

  it('if provided with invalid app name', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        apiClientId: APICLIENTID,
        applicationName: undefined,
        applicationDescription: 'bbb',
        websiteUrl: 'ccc',
        returnUrl: 'ddd',
      });
    }, /invalid application name/);
    done();
  });

  it('if provided with invalid app description', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        apiClientId: APICLIENTID,
        applicationName: 'aaa',
        applicationDescription: undefined,
        websiteUrl: 'ccc',
        returnUrl: 'ddd',
      });
    }, /invalid application description/);
    done();
  });

  it('if provided with invalid website url', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        apiClientId: APICLIENTID,
        applicationName: 'aaa',
        applicationDescription: 'bbb',
        websiteUrl: undefined,
        returnUrl: 'ddd',
      });
    }, /invalid website URL/);
    done();
  });

  it('if provided with invalid return url', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        apiClientId: APICLIENTID,
        applicationName: 'aaa',
        applicationDescription: 'bbb',
        websiteUrl: 'ccc',
        returnUrl: undefined,
      });
    }, /invalid return URL/);
    done();
  });
});

describe('ApiClientApplication.generateAuthorizationCode', () => {
  it('generates an authorization code', async () => {
    const app = new ApiClientApplication({
      apiClientId: APICLIENTID,
      applicationName: 'aaa',
      applicationDescription: 'bbb',
      websiteUrl: 'ccc',
      returnUrl: 'ddd',
      clientId: 'eee',
      clientSecret: 'fff',
    });

    const result = await ApiClientApplication.generateAuthorizationCode(app);
    assert(result instanceof ApiClientApplication);
    assert(result.authorizationCode !== '');
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
      apiClientId: APICLIENTID,
      applicationName: 'aaa',
      applicationDescription: 'bbb',
      websiteUrl: 'ccc',
      returnUrl: 'ddd',
      clientId: 'eee',
      clientSecret: 'fff',
    });

    const result = await ApiClientApplication.generateAuthorizationCode(app);
    assert(result instanceof ApiClientApplication);
    assert(result.authorizationCode !== '');
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
