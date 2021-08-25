const assert = require('assert');
const Address = require('../../../../lib/models/documents/sso/address');

describe('Address empty', () => {
  const address = new Address({
    user_id: 'a',
    line1: 'b',
    postCode: 'c',
    city: 'd',
    country: 'GB',
  });

  it('Creates a basic address', (done) => {
    assert(typeof address === 'object');
    assert(address.user_id === 'a');
    assert(address.line1 === 'b');
    assert(address.line2 === '');
    assert(address.line3 === '');
    assert(address.postCode === 'c');
    assert(address.city === 'd');
    assert(address.state === '');
    assert(address.country === 'GB');
    assert(address.isDefault === false);
    assert(address.isBilling === false);
    assert(address.isShipping === false);
    done();
  });

  it('Symbol.species', (done) => {
    assert(address instanceof Address);
    done();
  });

  it('A address gives a basic string', (done) => {
    // console.log(address.toString());
    assert(address.toString() === 'b, c, d, GB');
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
    const address = new Address({ user_id: 'a', line1, line2, line3, postCode, city, state, country });
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
    const address = new Address({ user_id: 'a', line1, line2, line3, postCode, city, state, country });
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

  it('if not provided with user_id', (done) => {
    assert.throws(() => {
      const line1 = '';
      const line2 = 'a';
      new Address({ line1, line2 });
    }, /invalid user identifier/);
    done();
  });

  it('if not provided with line1 but has line2', (done) => {
    assert.throws(() => {
      const user_id = 'xxx';
      const line1 = '';
      const line2 = 'a';
      new Address({ user_id, line1, line2 });
    }, /invalid address: field 'line1'/);
    done();
  });

  it('if not provided with line1 but has line3', (done) => {
    assert.throws(() => {
      const user_id = 'xxx';
      const line1 = '';
      const line3 = 'a';
      new Address({ user_id, line1, line3 });
    }, /invalid address: field 'line1'/);
    done();
  });

  it('if provided with line1 but not with postCode', (done) => {
    assert.throws(() => {
      const user_id = 'xxx';
      const line1 = 'a';
      const postCode = '';
      new Address({ user_id, line1, postCode });
    }, /invalid address: field 'line1'/);
    done();
  });

  it('if provided with line1 but not with city', (done) => {
    assert.throws(() => {
      const user_id = 'xxx';
      const line1 = 'a';
      const city = '';
      new Address({ user_id, line1, city });
    }, /invalid address: field 'line1'/);
    done();
  });

  it('if provided with line1 but not with country', (done) => {
    assert.throws(() => {
      const user_id = 'xxx';
      const line1 = 'a';
      const country = '';
      new Address({ user_id, line1, country });
    }, /invalid address: field 'line1'/);
    done();
  });

  it('if provided with no state but with country US', (done) => {
    assert.throws(() => {
      const user_id = 'xxx';
      const line1 = 'a';
      const postCode = 'sss';
      const city = 'xxx';
      const state = '';
      const country = 'US';
      new Address({ user_id, line1, postCode, city, state, country });
    }, /invalid state/);
    done();
  });
});
