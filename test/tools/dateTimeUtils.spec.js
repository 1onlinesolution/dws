const assert = require('assert');
const DateTimeUtils = require('../../lib/tools/dateTimeUtils');


describe('DateTimeUtils.dateToUTC', () => {
  // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/getUTCFullYear
  // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/getUTCDate
  const date1 = 'December 31, 1975, 23:15:30 GMT+11:00';
  const date2 = 'December 31, 1975, 23:15:30 GMT-11:00';

  let dateUTC1, dateUTC2;

  before(() => {
    // runs before all tests in this block
    dateUTC1 = DateTimeUtils.dateToUTC(DateTimeUtils.parse(date1));
    dateUTC2 = DateTimeUtils.dateToUTC(DateTimeUtils.parse(date2));
  });

  after(() => {
    // runs after all tests in this block
  });

  beforeEach(() => {
    // runs before each test in this block
  });

  afterEach(() => {
    // runs after each test in this block
  });

  it('returns correct year', () => {
    assert(dateUTC1.getFullYear() === 1975);
    assert(dateUTC2.getFullYear() === 1976);
  });

  it('returns correct date', () => {
    assert(dateUTC1.getDate() === 31);
    assert(dateUTC2.getDate() === 1);
  });

  it('returns correct hours', () => {
    assert(dateUTC1.getHours() === 12);
    assert(dateUTC2.getHours() === 10);
  });

  it('returns correct minutes', () => {
    assert(dateUTC1.getMinutes() === 15);
    assert(dateUTC2.getMinutes() === 15);
  });

  it('returns correct seconds', () => {
    assert(dateUTC1.getSeconds() === 30);
    assert(dateUTC2.getSeconds() === 30);
  });
});
