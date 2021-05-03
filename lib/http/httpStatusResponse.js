const HttpStatus = require('./httpStatus');
const DateTimeUtils = require('../tools/dateTimeUtils');

const response = (status, value, error = undefined, ip = undefined) => {
  return {
    status: status,
    success: status < 400,
    ip: ip,
    timestamp: DateTimeUtils.currentUtcDate(),
    error: error,
    value: value,
  };
};


class HttpStatusResponse {
  /**
   * 200: Success:
   * This code indicates a full success. Nothing went wrong even remotely.
   */
  static ok(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusOk, value || HttpStatus.statusNameOk, error, ip);
  }

  /**
   * 201: Created:
   * This code is used mainly for REST APIs when the client
   * requests to create a new entity in the server.
   */
  static created(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusCreated, value || HttpStatus.statusNameCreated, error, ip);
  }

  /**
   * 204: No LandingPageContent:
   * This is a successful code, but there is no content coming
   * back from the server. Sometimes, APIs returns 200, even if there is no content.
   */
  static noContent(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusNoContent, value || HttpStatus.statusNameNoContent, error, ip);
  }

  /**
   * 302: Found:
   * This code indicates that the user is required to perform a temporary redirect for some reason,
   * but the browsers started implementing this code as 303 See Other.
   * This lead to the introduction of the 303 and 307 Temporary redirect codes to disambiguate the overlap of behavior.
   */
  static found(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusFound, value || HttpStatus.statusNameFound, error, ip);
  }

  /**
   * 400: Bad Request:
   * This code indicates that the request from the user is syntactically incorrect.
   * There could be parameters missing or some of the values didn't pass validation.
   */
  static badRequest(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusBadRequest, value || HttpStatus.statusNameBadRequest, error, ip);
  }

  /**
   * 401: Unauthorized:
   * This code represents a lack of authentication of the client.
   * Usually, a valid login will fix this problem.
   */
  static unauthorized(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusUnauthorized, value || HttpStatus.statusNameUnauthorized, error, ip);
  }

  /**
   * 403: Forbidden:
   * This is similar to 401, but in this case,
   * it is indicating that the user does not have enough privileges.
   */
  static forbidden(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusForbidden, value || HttpStatus.statusNameForbidden, error, ip);
  }

  /**
   * 404: Not Found:
   * This means that the resource is not found in the server.
   * This is the error that you get when you navigate to a page that does not exist.
   */
  static notFound(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusNotFound, value || HttpStatus.statusNameNotFound, error, ip);
  }

  /**
   * 409: Conflict:
   * This means a request conflict with current state of the server.
   */
  static conflict(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusConflict, value || HttpStatus.statusNameConflict, error, ip);
  }

  /**
   * 422: Unprocessable Entity:
   * This means hat the server understands the content type of the request entity,
   * and the syntax of the request entity is correct,
   * but it was unable to process the contained instructions.
   */
  static unprocessableEntity(value, error= undefined, ip= undefined) {
    return response(HttpStatus.statusUnprocessableEntity, value || HttpStatus.statusNameUnprocessableEntity, error, ip);
  }

  /**
   * 500: Internal Server Error:
   * This means that an error has occurred in the software in the server.
   * There is no more information disclosed.
   */
  static serverError(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusServerError, value || HttpStatus.statusNameServerError, error, ip);
  }

  /**
   * 501: Not Implemented:
   * This error occurs when a client hits an endpoint that has not been implemented yet.
   */
  static notImplemented(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusNotImplemented, value || HttpStatus.statusNameNotImplemented, error, ip);
  }

  /**
   * 502: Bad Gateway:
   * A server (not necessarily a Web server) is acting as a gateway or proxy
   * to fulfil the request by the client (e.g. your Web browser or our CheckUpDown robot) to access the requested URL.
   * This server received an invalid response from an upstream server it accessed to fulfil the request.
   */
  static badGateway(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusBadGateway, value || HttpStatus.statusNameBadGateway, error, ip);
  }

  /**
   * 503: Service unavailable:
   * This code is issued when the server is not available for some reason,
   * either an excess of the load or the server is down.
   */
  static serviceUnavailable(value, error= undefined, ip = undefined) {
    return response(HttpStatus.statusServiceUnavailable, value || HttpStatus.statusNameServiceUnavailable, error, ip);
  }
}

module.exports = HttpStatusResponse;