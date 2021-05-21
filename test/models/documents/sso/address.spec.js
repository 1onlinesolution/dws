const assert = require('assert');
const Address = require('../../../../lib/models/documents/sso/address');

describe('Address empty', () => {
  it('Creates an empty address', (done) => {
    const address = new Address();
    assert(typeof address === 'object');
    assert(address.line1 === '');
    assert(address.line2 === '');
    assert(address.line3 === '');
    assert(address.postCode === '');
    assert(address.city === '');
    assert(address.state === '');
    assert(address.country === '');
    assert(address.isDefault === false);
    assert(address.isBilling === false);
    assert(address.isShipping === false);
    done();
  });

  it('Symbol.species', (done) => {
    const address = new Address();
    assert(address instanceof Address);
    done();
  });

  it('An empty address gives an empty string', (done) => {
    const address = new Address();
    assert(address.toString() === '');
    done();
  });

  it('A valid address gives the correct string representation', (done) => {
    const line1 = '12 Oxford Street';
    const line2 = 'Flackwell Heath';
    const line3 = 'lalala';
    const postCode = 'HP119EW';
    const city = 'Paris';
    const state = '';
    const country = 'IT';
    const address = new Address({line1, line2, line3, postCode, city, state, country});
    assert(address.toString() === `${line1}, ${line2}, ${line3}, ${postCode}, ${city}, ${country}`);
    done();
  });

  it('A valid US address gives the correct string representation', (done) => {
    const line1 = '12 Oxford Street';
    const line2 = 'Flackwell Heath';
    const line3 = 'lalala';
    const postCode = 'HP119EW';
    const city = 'Paris';
    const state = 'NJ';
    const country = 'US';
    const address = new Address({line1, line2, line3, postCode, city, state, country});
    assert(address.toString() === `${line1}, ${line2}, ${line3}, ${postCode}, ${city}, ${state}, ${country}`);
    done();
  });
});

describe('Address.checkForError throws or returns error', () => {
  it('if provided with null address', (done) => {
    const error = Address.checkForError(undefined);
    assert(error !== null);
    done();
  });

  it('if not provided with line1 but has line2', (done) => {
    assert.throws(() => {
      const line1 = '';
      const line2 = 'a';
      new Address({line1, line2 });
    }, /invalid address: field 'line1'/);
    done();
  });

  it('if not provided with line1 but has line3', (done) => {
    assert.throws(() => {
      const line1 = '';
      const line3 = 'a';
      new Address({line1, line3 });
    }, /invalid address: field 'line1'/);
    done();
  });

  it('if provided with line1 but not with postCode', (done) => {
    assert.throws(() => {
      const line1 = 'a';
      const postCode = '';
      new Address({line1, postCode });
    }, /invalid address: field 'line1'/);
    done();
  });

  it('if provided with line1 but not with city', (done) => {
    assert.throws(() => {
      const line1 = 'a';
      const city = '';
      new Address({line1, city });
    }, /invalid address: field 'line1'/);
    done();
  });

  it('if provided with line1 but not with country', (done) => {
    assert.throws(() => {
      const line1 = 'a';
      const country = '';
      new Address({line1, country });
    }, /invalid address: field 'line1'/);
    done();
  });

  it('if provided with no state but with country US', (done) => {
    assert.throws(() => {
      const line1 = 'a';
      const postCode = 'sss';
      const city = 'xxx';
      const state = '';
      const country = 'US';
      new Address({line1, postCode, city, state, country });
    }, /invalid state/);
    done();
  });
});
