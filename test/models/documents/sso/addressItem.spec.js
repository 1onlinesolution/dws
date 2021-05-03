const assert = require('assert');
const Address = require('../../../../lib/models/documents/sso/address');
const AddressItem = require('../../../../lib/models/documents/sso/addressItem');

describe('AddressItem empty', () => {
  it('Creates an empty address item', (done) => {
    const addressItem = new AddressItem();
    assert(typeof addressItem === 'object');
    assert(addressItem.address instanceof Address);
    assert(addressItem.isDefault === false);
    assert(addressItem.isBilling === false);
    assert(addressItem.isShipping === false);
    done();
  });

  it('Symbol.species', (done) => {
    const addressItem = new AddressItem();
    assert(addressItem instanceof AddressItem);
    done();
  });
});

describe('AddressItem.checkPassword throws or returns error', () => {
  it('if provided with null address', (done) => {
    assert.throws(() => {
      const address = null;
      new AddressItem({address });
    }, /invalid address/);
    done();
    // const error = AddressItem.checkForError(undefined);
    // assert(error !== null);
    // done();
  });

  // it('if provided with invalid address', (done) => {
  //   assert.throws(() => {
  //     const address = 'aaa';
  //     new AddressItem({address });
  //   }, /invalid address item/);
  //   done();
  // });

});
