const assert = require('assert');
const ApiClientApplication = require('../../../../lib/models/documents/sso/apiClientApplication');
const CreateApiClientApplicationParameters = require('../../../../lib/models/documents/sso/requestParams/createApiClientApplicationParameters');

describe('ApiClientApplication basic', () => {
  it('Creates an empty address item', (done) => {
    const app = new ApiClientApplication({
      applicationName: 'aaa',
      applicationDescription: 'bbb',
      websiteUrl: 'ccc',
      returnUrl: 'ddd',
      clientId: 'eee',
      clientSecret: 'fff',
    });

    assert(typeof app === 'object');
    assert(app.applicationName === 'aaa');
    assert(app.applicationDescription === 'bbb');
    assert(app.websiteUrl === 'ccc');
    assert(app.returnUrl === 'ddd');
    assert(app.clientId === 'eee');
    assert(app.clientSecret === 'fff');
    assert(app.createdAt instanceof Date);
    assert(app.modifiedAt instanceof Date);
    assert(app.authorizationCode === null);
    assert(app.authorizationCodeExpirationDate === null);
    assert(app.accessToken === null);
    assert(app.refreshToken === null);
    assert(app.expiresIn === null);

    done();
  });

  it('Symbol.species', (done) => {
    const app = new ApiClientApplication({
      applicationName: 'aaa',
      applicationDescription: 'bbb',
      websiteUrl: 'ccc',
      returnUrl: 'ddd',
      clientId: 'eee',
      clientSecret: 'fff',
    });

    assert(app instanceof ApiClientApplication);
    done();
  });

  it('gives a payload an authorization code', (done) => {
    const app = new ApiClientApplication({
      applicationName: 'aaa',
      applicationDescription: 'bbb',
      websiteUrl: 'ccc',
      returnUrl: 'ddd',
      clientId: 'eee',
      clientSecret: 'fff',
    });

    const payload = app.getPayload();
    assert(typeof payload === 'object');
    assert(payload.applicationName === app.applicationName);
    done();
  });

  it('creates tokens', async () => {
    const app = new ApiClientApplication({
      applicationName: 'aaa',
      applicationDescription: 'bbb',
      websiteUrl: 'ccc',
      returnUrl: 'ddd',
      clientId: 'eee',
      clientSecret: 'fff',
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

  it('if provided with invalid app name', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        applicationName: undefined,
        applicationDescription: 'bbb',
        websiteUrl: 'ccc',
        returnUrl: 'ddd',
        clientId: 'eee',
        clientSecret: 'fff',
      });
    }, /invalid application name/);
    done();
  });

  it('if provided with invalid app description', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        applicationName: 'aaa',
        applicationDescription: undefined,
        websiteUrl: 'ccc',
        returnUrl: 'ddd',
        clientId: 'eee',
        clientSecret: 'fff',
      });
    }, /invalid application description/);
    done();
  });

  it('if provided with invalid website url', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        applicationName: 'aaa',
        applicationDescription: 'bbb',
        websiteUrl: undefined,
        returnUrl: 'ddd',
        clientId: 'eee',
        clientSecret: 'fff',
      });
    }, /invalid website URL/);
    done();
  });

  it('if provided with invalid return url', (done) => {
    assert.throws(() => {
      new ApiClientApplication({
        applicationName: 'aaa',
        applicationDescription: 'bbb',
        websiteUrl: 'ccc',
        returnUrl: undefined,
        clientId: 'eee',
        clientSecret: 'fff',
      });
    }, /invalid return URL/);
    done();
  });

  it('if provided with invalid client identifier', (done) => {
    assert.throws(() => {
      const applicationName = 'aaa';
      const applicationDescription = 'bbb';
      const websiteUrl = 'ccc';
      const returnUrl = 'ddd';
      const clientId = undefined;
      const clientSecret = 'fff';
      const createdAt = undefined;
      const modifiedAt = undefined;
      const authorizationCode = null;
      const authorizationCodeExpirationDate = null;

      new ApiClientApplication({
        applicationName,
        applicationDescription,
        websiteUrl,
        returnUrl,
        clientId,
        clientSecret,
        createdAt,
        modifiedAt,
        authorizationCode,
        authorizationCodeExpirationDate,
      });
    }, /invalid client identifier/);
    done();
  });

  it('if provided with invalid client secret', (done) => {
    assert.throws(() => {
      const applicationName = 'aaa';
      const applicationDescription = 'bbb';
      const websiteUrl = 'ccc';
      const returnUrl = 'ddd';
      const clientId = 'eee';
      const clientSecret = undefined;
      const createdAt = undefined;
      const modifiedAt = undefined;
      const authorizationCode = null;
      const authorizationCodeExpirationDate = null;

      new ApiClientApplication({
        applicationName,
        applicationDescription,
        websiteUrl,
        returnUrl,
        clientId,
        clientSecret,
        createdAt,
        modifiedAt,
        authorizationCode,
        authorizationCodeExpirationDate,
      });
    }, /invalid client secret/);
    done();
  });
});

describe('ApiClientApplication.createApiClientApplication', () => {
  it('creates an object', async () => {
    const params = new CreateApiClientApplicationParameters({
      email: 'aaa@aaa.com',
      applicationName: 'bbb',
      applicationDescription: 'ccc',
      websiteUrl: 'ddd',
      returnUrl: 'eee',
    });
    const item = await ApiClientApplication.createApiClientApplication(params);
    assert(item instanceof ApiClientApplication);
  });

  it('throws if provided with invalid params', async () => {
    try {
      await ApiClientApplication.createApiClientApplication(null);
    } catch (err) {
      assert(err.name === 'Error');
      assert(err.message === 'invalid parameters');
    }
  });
});

describe('ApiClientApplication.generateAuthorizationCode', () => {
  it('generates an authorization code', async () => {
    const app = new ApiClientApplication({
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
