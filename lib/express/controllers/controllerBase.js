const { ipAddress } = require('@1onlinesolution/dws-http');
const ExpressApplication = require('../expressApplication');

class ControllerBase {
  constructor(expressApp) {
    if (!expressApp || !(expressApp instanceof ExpressApplication)) return new Error('invalid express application');
    this.expressApp = expressApp;
    this._database = expressApp.database;
  }

  get database() {
    return this._database;
  }

  log(req, error, data, message) {
    const messageCombined = `ip: ${ipAddress(req)} - error: ${error}, message: ${message}, reason: ${this.database.errorMessage(error)}`;
    this.expressApp.logError(messageCombined, {
      ip: ipAddress(req),
      error: error,
      stack: error.stack,
      message: message
    });

    if (req.flash) {
      if (data) req.flash('data', data);
      req.flash('error', `Error: ${message}`);
    }
  }

  prepareEmailOptions(request) {
    return {
      ip: ipAddress(request),
      host: `${request.protocol}://${request.headers.host}`,
    };
  }
}

module.exports = ControllerBase;
