const ExpressApplication = require('../expressApplication');
const ipAddress = require('../../http/ipAddress');

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
    this.expressApp.logError(`ip: ${ipAddress(req)} - error: ${error}, message: ${message}, reason: ${error.message}`);

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
