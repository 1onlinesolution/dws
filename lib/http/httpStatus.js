const DateTimeUtils = require('../tools/dateTimeUtils');
const ipAddress = require('./ipAddress');

const assembleJsonResponseWithError = (status, ipAddress, value, error = undefined) => {
  return {
    status: status,
    success: status < 400,
    ip: ipAddress,
    timestamp: DateTimeUtils.currentUtcDate(),
    error: error,
    value: value,
  };
};

const jsonResponse = (status, ipAddress, value, error = undefined) =>
  assembleJsonResponseWithError(status, ipAddress, value, error);

const response = (req, res, status, value, error = undefined) => {
  const responseData = jsonResponse(status, ipAddress(req), value, error);
  return res.json(responseData);
};

class HttpStatus {
  static get statusOk() { return 200; }
  static get statusCreated() { return 201; }
  static get statusNoContent() { return 204; }
  static get statusFound() { return 302; }
  static get statusBadRequest() { return 400; }
  static get statusUnauthorized() { return 401; }
  static get statusForbidden() { return 403; }
  static get statusNotFound() { return 404; }
  static get statusConflict() { return 409; }
  static get statusUnprocessableEntity() { return 422; }
  static get statusServerError() { return 500; }
  static get statusNotImplemented() { return 501; }
  static get statusBadGateway() { return 502; }
  static get statusServiceUnavailable() { return 503; }

  static get statusNameOk() { return 'Ok'; }
  static get statusNameCreated() { return 'Created'; }
  static get statusNameNoContent() { return 'No Content'; }
  static get statusNameFound() { return 'Found'; }
  static get statusNameBadRequest() { return 'BadRequest'; }
  static get statusNameUnauthorized() { return 'Unauthorized'; }
  static get statusNameForbidden() { return 'Forbidden'; }
  static get statusNameNotFound() { return 'Not Found'; }
  static get statusNameConflict() { return 'Conflict'; }
  static get statusNameUnprocessableEntity() { return 'Unprocessable Entity'; }
  static get statusNameServerError() { return 'Internal Server Error'; }
  static get statusNameNotImplemented() { return 'Not Implemented'; }
  static get statusNameBadGateway() { return 'Bad Gateway'; }
  static get statusNameServiceUnavailable() { return 'Service Unavailable'; }

  static fromHttpStatusResponse(req, res, httpStatusResponse) {
    return response(req, res, httpStatusResponse.status, httpStatusResponse.value, httpStatusResponse.error);
  }

  /**
   * 200: Success:
   * This code indicates a full success. Nothing went wrong even remotely.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @returns {*}
   */
  static ok(req, res, value = HttpStatus.statusNameOk) {
    return response(req, res, HttpStatus.statusOk, value);
  }

  /**
   * 201: Created:
   * This code is used mainly for REST APIs when the client
   * requests to create a new entity in the server.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @returns {*}
   */
  static created(req, res, value = HttpStatus.statusNameCreated) {
    return response(req, res, HttpStatus.statusCreated, value);
  }

  /**
   * 204: No LandingPageContent:
   * This is a successful code, but there is no content coming
   * back from the server. Sometimes, APIs returns 200, even if there is no content.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @returns {*}
   */
  static noContent(req, res, value = HttpStatus.statusNameNoContent) {
    return response(req, res, HttpStatus.statusNoContent, value);
  }

  /**
   * 302: Found:
   * This code indicates that the user is required to perform a temporary redirect for some reason,
   * but the browsers started implementing this code as 303 See Other.
   * This lead to the introduction of the 303 and 307 Temporary redirect codes to disambiguate the overlap of behavior.
   * @param req
   * @param res
   * @param value
   * @returns {*}
   */
  static found(req, res, value = HttpStatus.statusNameFound) {
    return response(req, res, HttpStatus.statusFound, value);
  }

  /**
   * 400: Bad Request:
   * This code indicates that the request from the user is syntactically incorrect.
   * There could be parameters missing or some of the values didn't pass validation.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @param error Error returned.
   * @returns {*}
   */
  static badRequest(req, res, value = HttpStatus.statusNameBadRequest, error = undefined) {
    return response(req, res, HttpStatus.statusBadRequest, value, error);
  }

  /**
   * 401: Unauthorized:
   * This code represents a lack of authentication of the client.
   * Usually, a valid login will fix this problem.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @param error Error returned.
   * @returns {*}
   */
  static unauthorized(req, res, value = HttpStatus.statusNameUnauthorized, error = undefined) {
    return response(req, res, HttpStatus.statusUnauthorized, value, error);
  }

  /**
   * 403: Forbidden:
   * This is similar to 401, but in this case,
   * it is indicating that the user does not have enough privileges.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @param error Error returned.
   * @returns {*}
   */
  static forbidden(req, res, value = HttpStatus.statusNameForbidden, error = undefined) {
    return response(req, res, HttpStatus.statusForbidden, value, error);
  }

  /**
   * 404: Not Found:
   * This means that the resource is not found in the server.
   * This is the error that you get when you navigate to a page that does not exist.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @param error Error returned.
   * @returns {*}
   */
  static notFound(req, res, value = HttpStatus.statusNameNotFound, error = undefined) {
    return response(req, res, HttpStatus.statusNotFound, value, error);
  }

  /**
   * 409: Conflict:
   * This means a request conflict with current state of the server.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @param error Error returned.
   * @returns {*}
   */
  static conflict(req, res, value = HttpStatus.statusNameConflict, error = undefined) {
    return response(req, res, HttpStatus.statusConflict, value, error);
  }

  /**
   * 422: Unprocessable Entity:
   * This means hat the server understands the content type of the request entity,
   * and the syntax of the request entity is correct,
   * but it was unable to process the contained instructions.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @param error Error returned.
   * @returns {*}
   */
  static unprocessableEntity(req, res, value = HttpStatus.statusNameUnprocessableEntity, error = undefined) {
    return response(req, res, HttpStatus.statusUnprocessableEntity, value, error);
  }

  /**
   * 500: Internal Server Error:
   * This means that an error has occurred in the software in the server.
   * There is no more information disclosed.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @param error Error returned.
   * @returns {*}
   */
  static serverError(req, res, value = HttpStatus.statusNameServerError, error = undefined) {
    return response(req, res, HttpStatus.statusServerError, value, error);
  }

  /**
   * 501: Not Implemented:
   * This error occurs when a client hits an endpoint that has not been implemented yet.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @param error Error returned.
   * @returns {*}
   */
  static notImplemented(req, res, value = HttpStatus.statusNameNotImplemented, error = undefined) {
    return response(req, res, HttpStatus.statusNotImplemented, value, error);
  }

  /**
   * 502: Bad Gateway:
   * A server (not necessarily a Web server) is acting as a gateway or proxy
   * to fulfil the request by the client (e.g. your Web browser or our CheckUpDown robot) to access the requested URL.
   * This server received an invalid response from an upstream server it accessed to fulfil the request.
   * @param req The client request.
   * @param res The server response.
   * @param value The return value.
   * @param error Error returned.
   * @returns {*}
   */
  static badGateway(req, res, value = HttpStatus.statusNameBadGateway, error = undefined) {
    return response(req, res, HttpStatus.statusBadGateway, value, error);
  }

  /**
   * 503: Service unavailable:
   * This code is issued when the server is not available for some reason,
   * either an excess of the load or the server is down.
   * @param req
   * @param res
   * @param value
   * @param error
   * @returns {*}
   */
  static serviceUnavailable(req, res, value = HttpStatus.statusNameServiceUnavailable, error = undefined) {
    return response(req, res, HttpStatus.statusServiceUnavailable, value, error);
  }

  // ===========================================================================
  static ignoreFavicon(req, res, next) {
    if (req.originalUrl === '/favicon.ico') {
      return HttpStatus.noContent(req, res);
    } else {
      next();
    }
  }
}

module.exports = HttpStatus;
