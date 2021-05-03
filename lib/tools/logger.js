const winston = require('winston');
// Import mongodb: https://github.com/winstonjs/winston-mongodb
// Requiring 'winston-mongodb' will expose 'winston.transports.MongoDB'
require('winston-mongodb');

// const path = require('path');
// const winston = require('winston');
const { createLogger, transports, format } = winston;
const { combine, splat, timestamp, printf } = format;

// https://github.com/winstonjs/winston/blob/2625f60c5c85b8c4926c65e98a591f8b42e0db9a/README.md#logging-levels
// https://github.com/winstonjs/winston/blob/2625f60c5c85b8c4926c65e98a591f8b42e0db9a/README.md#creating-custom-formats
const myFormat = printf(({ level, message, label, timestamp /*, ...metadata*/ }) => {
  // let msg = `${timestamp} [${label}] [${level}]: ${message}`;
  // if (metadata) {
  //   const extra = ' ' + JSON.stringify(metadata);
  //   msg += extra;
  // }
  // return msg;
  return `${timestamp} [${label}] [${level}]: ${message}`;
});

class Logger {
  constructor({
    label = undefined,
    useConsole = true,
    useMongoDB = true,
    mongoLevel = 'error',
    consoleLevel = 'warn',
    mongoUri = undefined,
    mongoCollectionName = undefined,
    mongoOptions = {
      level: mongoLevel || 'error',
      //mongo database connection link
      db: mongoUri,
      options: {
        poolSize: 2,
        // autoReconnect: true, // Deprecated...
        useNewUrlParser: true,
        useUnifiedTopology: true,
      },
      // A collection to save json formatted logs
      collection: mongoCollectionName,
      capped: true,
      cappedMax: 10000,
    },
    consoleOptions = {
      level: consoleLevel || 'warn',
    },
  }) {
    this.label = label;
    this.useConsole = useConsole;
    this.useMongoDB = useMongoDB;
    this.mongoUri = mongoUri;
    this.consoleLevel = consoleLevel;
    this.mongoLevel = mongoLevel;
    this.mongoCollectionName = mongoCollectionName;
    this.mongoOptions = mongoOptions;
    this.consoleOptions = consoleOptions;

    this.transports = [];

    if (this.useConsole) {
      this.consoleOptions.format = combine(format.label({ label: this.label }), timestamp(), format.colorize(), splat(), myFormat);

      // only logs errors and warnings to the console
      const consoleTransport = new transports.Console(this.consoleOptions);
      this.transports.push(consoleTransport);
    }

    if (this.useMongoDB) {
      this.mongoOptions.format = format.combine(
        format.timestamp(),
        // Convert logs to a json format
        format.json(),
      );

      // MongoDB transport
      const mongoTransport = new transports.MongoDB(this.mongoOptions);
      this.transports.push(mongoTransport);

      // // all logs will be saved to this app.log file
      // new (transports.File)({
      //   filename: path.resolve(__dirname, '../logs/app.log')
      // }),
      //
      // // only errors will be saved to errors.log, and we can examine
      // // app.log for more context and details if needed.
      // new (transports.File)({
      //   level: 'error',
      //   filename: path.resolve(__dirname, '../logs/errors.log')
      // }),
    }

    const logger = new createLogger({
      transports: this.transports,
      exitOnError: false, // do not exit on handled exceptions
    });

    // create a stream object with a 'write' function that will be used by `morgan`
    /* eslint-disable no-unused-vars */
    logger.stream = {
      write: function (message, encoding) {
        // use the 'info' log level so the output will be picked up by both transports (mongodb and console)
        logger.info(message);
      },
    };
    /* eslint-enable no-unused-vars */

    this.logger = logger;

    return this;
  }

  get stream() {
    return this.logger.stream;
  }

  warn(message) {
    return this.logger.warn(message);
  }

  info(message) {
    return this.logger.info(message);
  }

  error(message) {
    return this.logger.error(message);
  }
}

module.exports = Logger;
