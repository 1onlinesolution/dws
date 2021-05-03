const Validity = require('../../../tools/validity');
const DateTimeUtils = require('../../../tools/dateTimeUtils');

class UserStatistics {
  constructor({ lastLoggedInAt = null, countLogIns = 0, countJwtGenerations = 0, countEngineRunTimeInSeconds = 0 } = {}) {
    this.lastLoggedInAt = lastLoggedInAt ? new Date(lastLoggedInAt) : DateTimeUtils.currentUtcDate();
    this.countLogIns = countLogIns;
    this.countJwtGenerations = countJwtGenerations;
    this.countEngineRunTimeInSeconds = countEngineRunTimeInSeconds;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  checkForError() {
    return UserStatistics.checkForError(this);
  }

  static get [Symbol.species]() {
    return this;
  }

  static checkForError(stats) {
    if (!stats || !(stats instanceof UserStatistics)) return new Error('invalid user statistics');
    if (!Validity.isValidDate(stats.lastLoggedInAt)) return new Error('invalid last login date');
    if (!Validity.isValidNumber(stats.countLogIns, 0)) return new Error('invalid user login counts');
    if (!Validity.isValidNumber(stats.countJwtGenerations, 0)) return new Error('invalid JWT generations count');
    if (!Validity.isValidNumber(stats.countEngineRunTimeInSeconds, 0))
      return new Error('invalid engine run time count');
    return null;
  }
}

module.exports = UserStatistics;
