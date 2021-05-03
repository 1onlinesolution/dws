const assert = require('assert');
const Converter = require('../../lib/tools/converter');

// https://nodejs.org/api/assert.html#assert_assert_throws_block_error_message

describe('Converter.toBoolean', () => {
  // Falsy Values
  // false
  // undefined
  // null
  // NaN
  // 0
  // '' (empty string)

  it('Converts falsy values to false', (done) => {
    assert(Converter.toBoolean(false) === false);
    assert(Converter.toBoolean(undefined) === false);
    assert(Converter.toBoolean(null) === false);
    assert(Converter.toBoolean(NaN) === false);
    assert(Converter.toBoolean(0) === false);
    assert(Converter.toBoolean('') === false);
    done();
  });

  it('Converts boolean to true', (done) => {
    assert(Converter.toBoolean(true) === true);
    done();
  });

  it('Converts boolean to false', (done) => {
    assert(Converter.toBoolean([]) === false);
    done();
  });

  it('Converts boolean to false', (done) => {
    assert(Converter.toBoolean(false) === false);
    done();
  });

  it('Converts undefined to false', (done) => {
    assert(Converter.toBoolean() === false);
    done();
  });

  it('Converts string to true', (done) => {
    assert(Converter.toBoolean('True') === true);
    done();
  });

  it('Converts string to false', (done) => {
    assert(Converter.toBoolean('Truee') === false);
    done();
  });

  it('Converts string to false', (done) => {
    assert(Converter.toBoolean('Tru') === false);
    done();
  });

  it('Converts string to false', (done) => {
    assert(Converter.toBoolean('FalSe') === false);
    done();
  });

  it('Converts empty string to false', (done) => {
    assert(Converter.toBoolean('') === false);
    done();
  });
});

describe('Converter.ms', () => {
  it('Converts successfully', (done) => {
    assert(Converter.ms('2 days') === 172800000);
    assert(Converter.ms('1d') === 86400000);
    assert(Converter.ms('10h') === 36000000);
    assert(Converter.ms('2.5 hrs') === 9000000);
    assert(Converter.ms('2h') === 7200000);

    assert(Converter.ms('1m') === 60000);
    assert(Converter.ms('1minutes') === 60000);
    assert(Converter.ms('1minute') === 60000);
    assert(Converter.ms('1mins') === 60000);
    assert(Converter.ms('1min') === 60000);

    assert(Converter.ms('5s') === 5000);
    assert(Converter.ms('5seconds') === 5000);
    assert(Converter.ms('5second') === 5000);
    assert(Converter.ms('5secs') === 5000);
    assert(Converter.ms('5sec') === 5000);

    assert(Converter.ms('5ms') === 5);
    assert(Converter.ms('5milliseconds') === 5);
    assert(Converter.ms('5millisecond') === 5);
    assert(Converter.ms('5msecs') === 5);
    assert(Converter.ms('5msec') === 5);

    assert(Converter.ms('1y') === 31557600000);
    assert(Converter.ms('1year') === 31557600000);
    assert(Converter.ms('1yr') === 31557600000);
    assert(Converter.ms('1 years') === 31557600000);
    assert(Converter.ms('1 yrs') === 31557600000);
    assert(Converter.ms('100') === 100);
    assert(Converter.ms('-3 days') === -259200000);
    assert(Converter.ms('-1h') === -3600000);
    assert(Converter.ms('-200') === -200);

    assert(Converter.ms('3 weeks') > 0);
    assert(Converter.ms('1 week') > 0);
    assert(Converter.ms('3 w') > 0);
    done();
  });

  it('Converts successfully from number', (done) => {
    assert(Converter.ms(60000) === '1m');
    assert(Converter.ms(2 * 60000) === '2m');
    assert(Converter.ms(-3 * 60000) === '-3m');
    assert(Converter.ms(Converter.ms('10 hours')) === '10h');

    assert(Converter.ms(60000, { long: true }) === '1 minute');
    assert(Converter.ms(2 * 60000, { long: true }) === '2 minutes');
    assert(Converter.ms(-3 * 60000, { long: true }) === '-3 minutes');
    assert(Converter.ms(Converter.ms('10 hours'), { long: true }) === '10 hours');

    assert(Converter.ms(Converter.ms('10 days'), { long: true }) === '10 days');
    assert(Converter.ms(Converter.ms('10 days'), { long: false }) === '10d');

    assert(Converter.ms(Converter.ms('10 milliseconds'), { long: true }) === '10 ms');
    assert(Converter.ms(Converter.ms('10 milliseconds'), { long: false }) === '10ms');

    assert(Converter.ms(Converter.ms('10 seconds'), { long: true }) === '10 seconds');
    assert(Converter.ms(Converter.ms('10 seconds'), { long: false }) === '10s');
    done();
  });
});

describe('Converter.toSeconds', () => {
  it('Converts successfully', (done) => {
    assert(Converter.toSeconds('2 days') === 172800);
    assert(Converter.toSeconds('1d') === 86400);
    assert(Converter.toSeconds('10h') === 36000);
    assert(Converter.toSeconds('2.5 hrs') === 9000);
    assert(Converter.toSeconds('2h') === 7200);
    assert(Converter.toSeconds('1m') === 60);
    assert(Converter.toSeconds('5s') === 5);
    assert(Converter.toSeconds('1y') === 31557600);
    assert(Converter.toSeconds('100') === 0.1);
    assert(Converter.toSeconds('-3 days') === -259200);
    assert(Converter.toSeconds('-1h') === -3600);
    assert(Converter.toSeconds('-200') === -0.2);
    done();
  });
});

describe('Converter.ms throws', () => {
  it('Ctor throws if object provided', (done) => {
    assert.throws(() => {
      Converter.ms({ data: '1' });
    }, /val is not a non-empty string or a valid number/);
    // or this (see passwordService.spec.js for async/await example):
    // try {
    //     new EmailHandler();
    // }
    // catch(err){
    //     assert.equal(err.name, 'SmtpConfigurationError');
    //     assert.equal(err.message, msg);
    // }
    done();
  });

  it('Ctor throws if string length is greater than 100', (done) => {
    assert.throws(() => {
      Converter.ms(
        '1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890',
      );
    }, /String length should be up to 100 characters/);
    // or this (see passwordService.spec.js for async/await example):
    // try {
    //     new EmailHandler();
    // }
    // catch(err){
    //     assert.equal(err.name, 'SmtpConfigurationError');
    //     assert.equal(err.message, msg);
    // }
    done();
  });

  it('Ctor throws if string has invalid format', (done) => {
    assert.throws(() => {
      Converter.ms('123 hello world');
    }, /Invalid time format/);
    // or this (see passwordService.spec.js for async/await example):
    // try {
    //     new EmailHandler();
    // }
    // catch(err){
    //     assert.equal(err.name, 'SmtpConfigurationError');
    //     assert.equal(err.message, msg);
    // }
    done();
  });
});

describe('Converter.checkBoxToBoolean', () => {
  it('Converts to true', (done) => {
    assert(Converter.checkBoxToBoolean('lalala', 'lalala') === true);
    done();
  });

  it('Converts to false', (done) => {
    assert(Converter.checkBoxToBoolean(undefined) === false);
    done();
  });

  it('Converts to false', (done) => {
    assert(Converter.checkBoxToBoolean([]) === false);
    done();
  });
});
