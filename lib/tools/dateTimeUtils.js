// https://stackoverflow.com/a/6777470
// https://stackoverflow.com/a/14523953

class DateTimeUtils {
  static parse(dateAsString) {
    return new Date(Date.parse(dateAsString));
  }

  static dateToUTC(date) {
    const year = date.getUTCFullYear();
    const month = date.getUTCMonth();
    const day = date.getUTCDate();
    const hours = date.getUTCHours();
    const minutes = date.getUTCMinutes();
    const seconds = date.getUTCSeconds();
    return new Date(Date.UTC(year, month, day, hours, minutes, seconds));
  }

  static currentUtcDate() {
    const date = new Date();
    return DateTimeUtils.dateToUTC(date);
  }
}

module.exports = DateTimeUtils;