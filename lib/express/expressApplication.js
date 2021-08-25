const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const hbs = require('express-handlebars');
const cors = require('cors');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const session = require('@1onlinesolution/dws-session/lib/session');
const flash = require('connect-flash');
const methodOverride = require('method-override');
const compression = require('compression');
const morgan = require('morgan');
const MongoStore = require('connect-mongo');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');
const { Logger, consoleOptions, fileOptions, mongoOptions } = require('@1onlinesolution/dws-log');
const HttpStatus = require('@1onlinesolution/dws-http/lib/httpStatus');
const RouterInfo = require('./routerInfo');
const locals = require('./locals');

const isProduction = process.env.NODE_ENV === 'production';

class ExpressApplication {
  constructor({
    isApi = false,
    domain = undefined,
    useHelmet = true,
    useSession = true,
    useCookieParser = true,
    useCors = false,
    useFlash = true,
    useCompression = true,
    useCsurf = true,
    useMethodOverride = false,
    useBodyParser = true,
    useEngine = true,
    useLog = true,

    errorNotFoundHandler = undefined,
    errorHandler = undefined,

    helmetOptions = {
      frameguard: {
        action: 'deny',
      },
    },

    corsOrigin = '*',
    corsMethods = 'GET,HEAD,PUT,PATCH,POST,DELETE',
    corsPreflightContinue = false,
    corsOptionsSuccessStatus = 204,
    corsAllowedHeaders = ['Content-Type', 'Authorization'],

    sessionSecret = undefined,
    sessionName = domain,
    sessionMongoUrl = undefined,
    sessionTtl = 60 * 60, // TTL of 60 minutes represented in seconds
    sessionResave = false,
    sessionSaveUninitialized = false,

    cookieSecret = undefined,

    bodyParserUrlencoded = true,
    bodyParserJson = true,
    bodyParserUrlencodedExtended = false,
    bodyParserUrlencodedLimit = '10mb',
    bodyParserJsonLimit = '1mb',

    appDirName = undefined,
    staticPathDir = '/public',

    engineDefaultLayout = '',
    engineViewsDir = '',
    engineLayoutsDir = '',
    enginePartialsDir = '',
    engineHelpers = undefined,

    logLabel = undefined,
    logUseConsole = true,
    logUseMongoDB = true,
    logUseFile = true,

    logConsoleLevel = 'warn',
    logMongoLevel = 'error',
    logFileLevel = 'error',

    logMongoUrl = undefined,
    logMongoCollectionName = undefined,

    logFilePath = path.resolve(__dirname, 'logs/errors.log'),

    logMorganFormat = 'combine',
  }) {
    // =======================================================================
    // error checking
    if (!domain) throw new Error('invalid domain');
    if (useSession) {
      if (!sessionName) throw new Error('invalid session name');
      if (!sessionSecret) throw new Error('invalid session secret');
      if (!sessionMongoUrl) throw new Error('invalid session MongoDB url');
    }
    if (useCookieParser) {
      if (!cookieSecret) throw new Error('invalid cookie secret');
    }

    if (!appDirName || appDirName === '') throw new Error('invalid __dirname');

    if (useEngine) {
      if (!engineViewsDir || engineViewsDir === '') throw new Error('invalid engine views directory');
      if (!engineLayoutsDir || engineLayoutsDir === '') throw new Error('invalid engine layouts directory');
      if (!enginePartialsDir || enginePartialsDir === '') throw new Error('invalid engine partials directory');
    }
    if (useLog) {
      if (!logLabel) throw new Error('invalid log label');
      if (logUseMongoDB) {
        if (!logMongoUrl) throw new Error('invalid log MongoDB url');
        if (!logMongoCollectionName) throw new Error('invalid log MongoDB collection name');
      }
      if (logUseFile && !Validity.isValidString(logFilePath, 2)) throw new Error('invalid log file path');
    }

    this.isApi = isApi;

    this.domain = domain;

    this.useHelmet = useHelmet;
    this.useBodyParser = useBodyParser;
    this.useSession = useSession;
    this.useCookieParser = useCookieParser;
    this.useCors = useCors;
    this.useFlash = !this.isApi && useFlash;
    this.useCompression = useCompression;
    this.useCsurf = useCsurf;
    this.useMethodOverride = useMethodOverride;
    this.useEngine = !this.isApi && useEngine;
    this.useLog = useLog;

    this.errorNotFoundHandler = errorNotFoundHandler;
    this.errorHandler = errorHandler;

    this.helmetOptions = helmetOptions;

    // https://www.npmjs.com/package/cors#configuration-options
    this.corsOrigin = corsOrigin;
    this.corsMethods = corsMethods;
    this.corsPreflightContinue = corsPreflightContinue;
    this.corsOptionsSuccessStatus = corsOptionsSuccessStatus;
    this.corsAllowedHeaders = corsAllowedHeaders;

    this.bodyParserUrlencoded = bodyParserUrlencoded;
    this.bodyParserJson = bodyParserJson;
    this.bodyParserUrlencodedExtended = bodyParserUrlencodedExtended;
    this.bodyParserUrlencodedLimit = bodyParserUrlencodedLimit;
    this.bodyParserJsonLimit = bodyParserJsonLimit;

    this.logLabel = logLabel;
    this.logUseConsole = logUseConsole;
    this.logUseMongoDB = logUseMongoDB;
    this.logUseFile = logUseFile;

    this.logConsoleLevel = logConsoleLevel;
    this.logFileLevel = logFileLevel;
    this.logMongoLevel = logMongoLevel;

    this.logMongoUrl = logMongoUrl;
    this.logMongoCollectionName = logMongoCollectionName;
    this.logFilePath = logFilePath;
    this.logMorganFormat = logMorganFormat;

    this.sessionSecret = sessionSecret;
    this.sessionName = sessionName;
    this.sessionMongoUrl = sessionMongoUrl;
    this.sessionTtl = sessionTtl;
    this.sessionResave = sessionResave;
    this.sessionSaveUninitialized = sessionSaveUninitialized;

    this.cookieSecret = cookieSecret;

    this.staticPathDir = staticPathDir;
    this.appDirName = appDirName;

    this.engineDefaultLayout = engineDefaultLayout;
    this.engineViewsDir = engineViewsDir;
    this.engineLayoutsDir = engineLayoutsDir;
    this.enginePartialsDir = enginePartialsDir;
    this.engineHelpers = engineHelpers;

    this.logger = this.useLog ? new Logger(this.logOptions) : null;

    this._cookiesOptions = null;
    this._engineOptions = null;
    this._bodyParserOptions = null;
    this._sessionOptions = null;
    this._csrfOptions = null;
    this._logOptions = null;

    // =======================================================================
    // the express app
    this.app = express();

    // Middleware
    this.middleware = [];
    if (this.useHelmet) {
      // Contains HSTS also: https://helmetjs.github.io/
      this.app.use(helmet(this.helmetOptions));
    }

    if (this.useCors) {
      this.app.use(
        cors({
          origin: this.corsOrigin,
          methods: this.corsMethods,
          preflightContinue: this.corsPreflightContinue,
          optionsSuccessStatus: this.corsOptionsSuccessStatus,
          allowedHeaders: this.corsAllowedHeaders,
        }),
      );
    }

    if (this.useMethodOverride) {
      // TODO: improve this...
      this.app.use(methodOverride('_method'));
    }

    if (isProduction) {
      // Set trust proxy to true if your Node.js app is working behind reverse proxy such
      // as Varnish or Nginx. This will permit trusting in the X-Forwarded-* headers, such as
      // X-Forwarded-Proto (req.protocol) or X-Forwarder-For (req.ips). The trust proxy
      // setting is disabled by default.
      this.app.set('trust proxy', 1);

      // compress all responses in production
      if (this.useCompression) {
        this.app.use(compression());
      }
    }

    if (this.staticPathDir) {
      if (Validity.isValidString(this.staticPathDir)) {
        const staticPath = path.join(this.appDirName, this.staticPathDir);
        this.app.use(express.static(staticPath));
      } else if (Validity.isArray(this.staticPathDir)) {
        this.staticPathDir.forEach(item => {
          const staticPath = path.join(this.appDirName, item);
          this.app.use(express.static(staticPath));
        });
      }
    }

    if (this.useLog) {
      this.app.use(morgan(this.logMorganFormat, { stream: this.logger.stream }));
    }

    if (this.useEngine) {
      // view engine setup
      this.app.engine('hbs', hbs(this.engineOptions));
      this.app.set('views', path.join(this.appDirName, this.engineViewsDir));
      this.app.set('view engine', 'hbs');
    }

    if (this.useBodyParser) {
      if (this.bodyParserUrlencoded) {
        this.app.use(
          bodyParser.urlencoded({
            extended: this.bodyParserOptions.urlencoded_extended, // ALWAYS !
            limit: this.bodyParserOptions.urlencoded_limit,
          }),
        );
      }

      if (this.bodyParserJson) {
        this.app.use(bodyParser.json({ limit: this.bodyParserOptions.json_limit }));
      }
    }

    if (this.useCookieParser) {
      this.app.use(cookieParser(this.cookieSecret, this.cookiesOptions));
    }

    if (this.useSession) {
      this.app.use(session(this.sessionOptions));
    }

    if (this.useCsurf) {
      this.app.use(csrf(this.csrfOptions));
    }

    if (this.useFlash) {
      // DO NOT USE FLASH WITHOUT SESSION !!!
      // Flash requires a session, so once logged out you can't use it !!!
      this.app.use(flash());
    }

    this.app.use(locals);

    // Routes
    this.routers = new Map();
    // if (routers) {
    //   routers.forEach((routerInfo) => {
    //     if (!(routerInfo instanceof RouterInfo)) throw new Error('invalid router information');
    //     this.routers.set(routerInfo.path, routerInfo.router);
    //   });
    // }

    // Errors/NotFound
    if (!this.errorNotFoundHandler) this.errorNotFoundHandler = defaultErrorNotFoundHandler();
    if (!this.errorHandler) this.errorHandler = defaultErrorHandler(this);

    this.isListening = false;
    return this;
  }

  get engineOptions() {
    if (!this._engineOptions) {
      this._engineOptions = {
        extname: 'hbs',
        defaultLayout: this.engineDefaultLayout,
        layoutsDir: path.join(this.appDirName, this.engineLayoutsDir),
        partialsDir: path.join(this.appDirName, this.enginePartialsDir),
        helpers: require('./viewsEngine/helpers'),
      };

      if (this.engineHelpers) {
        this._engineOptions.helpers = this.engineHelpers;
      }

      Object.freeze(this._engineOptions);
    }

    return this._engineOptions;
  }

  get logOptions() {
    if (!this._logOptions) {

      consoleOptions.level = this.logConsoleLevel;

      mongoOptions.db = this.logMongoUrl;
      mongoOptions.collection = this.logMongoCollectionName;
      mongoOptions.level = this.logMongoLevel;

      fileOptions.level = this.logFileLevel;
      fileOptions.filename = this.logFilePath;

      this._logOptions = {
        label: this.logLabel,

        // Console
        useConsole: this.logUseConsole,
        consoleOptions: consoleOptions,

        // MongoDB
        useMongoDB: this.logUseMongoDB,
        mongoOptions: mongoOptions,

        // File
        useFile: this.logUseFile,
        fileOptions: fileOptions,
      };

      Object.freeze(this._logOptions);
    }

    return this._logOptions;
  }

  get cookiesOptions() {
    if (!this._cookiesOptions) {
      this._cookiesOptions = defaultCookiesOptions({ isProduction, domain: this.domain });

      Object.freeze(this._cookiesOptions);
    }

    return this._cookiesOptions;
  }

  get bodyParserOptions() {
    if (!this._bodyParserOptions) {
      this._bodyParserOptions = {
        urlencoded: this.bodyParserUrlencoded,
        json: this.bodyParserJson,
        urlencoded_extended: this.bodyParserUrlencodedExtended,
        urlencoded_limit: this.bodyParserUrlencodedLimit,
        json_limit: this.bodyParserJsonLimit,
      };

      Object.freeze(this._bodyParserOptions);
    }

    return this._bodyParserOptions;
  }

  get sessionOptions() {
    if (!this._sessionOptions) {
      this._sessionOptions = {
        secret: this.sessionSecret,
        name: this.sessionName, // <-- a less generic name for the session id
        store: MongoStore.create({
          mongoUrl: this.sessionMongoUrl,
          ttl: this.sessionTtl,
        }),
        resave: this.sessionResave,
        saveUninitialized: this.sessionSaveUninitialized,
      };

      Object.freeze(this._sessionOptions);
    }

    return this._sessionOptions;
  }

  get csrfOptions() {
    if (!this._csrfOptions) {
      // https://www.npmjs.com/package/csurf
      this._csrfOptions = {
        cookie: true,
      };
      if (isProduction) {
        this._csrfOptions.ignoreMethods = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'DELETE' /* etc */];
      }

      Object.freeze(this._csrfOptions);
    }

    return this._csrfOptions;
  }

  use(middleware) {
    if (middleware) {
      this.middleware.push(middleware);
    }
  }

  useErrorHandler(middleware) {
    if (middleware) {
      this.errorHandler = middleware;
    }
  }

  useStatic(path) {
    if (Validity.isValidString(path)) {
      this.app.use(express.static(path));
    }
  }

  listen(port = 3000, callback) {
    if (!port) throw new Error('invalid port');

    if (!this._isListening) {
      // this.app = express();

      initializeApplication(this);

      this.app.listen(port, () => {
        if (callback) callback();
      });

      this._isListening = true;
      Object.freeze(this._isListening);

      Object.freeze(this.middleware);
      Object.freeze(this.logger);
      Object.freeze(this.routers);
      Object.freeze(this.app);
    }
  }

  flash(req, mode, message) {
    // !!! NOTE: !!!
    // You must have a user session active for this to work !!!
    const { flash } = req;
    if (flash) flash(mode, message);
  }

  logWarn(message, meta) {
    if (this.useLog) this.logger.warn(message, meta);
  }

  logInfo(message, meta) {
    if (this.useLog) this.logger.info(message, meta);
  }

  logError(message, meta) {
    if (this.useLog) this.logger.error(message, meta);
  }

  addRouter(path, middleware = []) {
    // A router object is an isolated instance of middleware and routes.
    // You can think of it as a “mini-application,”
    // capable only of performing middleware and routing functions.
    // Every Express application has a built-in app router.
    //
    // A router behaves like middleware itself,
    // so you can use it as an argument to app.use()
    // or as the argument to another router’s use() method.
    const routerInfo = new RouterInfo(path, express.Router(), this, middleware);
    this.routers.set(path, routerInfo);
    return routerInfo;
  }

  getRouter(path) {
    return this.routers[path];
  }
}

module.exports = ExpressApplication;

function defaultCookiesOptions({ isProduction, domain }) {
  // https://expressjs.com/en/4x/api.html#res.cookie
  // https://www.npmjs.com/package/cookie
  return {
    // Specifies the boolean value for the Secure Set-Cookie attribute.
    // When truthy, the Secure attribute is set, otherwise it is not.
    // By default, the Secure attribute is not set.
    //
    // If you set the httpOnly flag on the cookie,
    // then all scripts running on the page are blocked
    // from accessing that cookie.
    secure: isProduction, // set the cookie only to be served with HTTPS

    // Specifies the boolean value for the HttpOnly Set-Cookie attribute.
    // When truthy, the HttpOnly attribute is set, otherwise it is not.
    // By default, the HttpOnly attribute is not set.
    //
    // NOTE: be careful when setting this to true,
    // as compliant clients will not allow client-side JavaScript to see the cookie in document.cookie
    httpOnly: true, // Mitigate XSS

    // Specifies the value for the Domain Set-Cookie attribute.
    // By default, no domain is set, and most clients will consider the cookie to apply to only the current domain.
    domain: isProduction ? domain : 'localhost', // i.e., limit the cookie exposure

    // Specifies the number (in seconds) to be the value for the Max-Age Set-Cookie attribute.
    // The given number will be converted to an integer by rounding down.
    // By default, no maximum age is set.
    //
    // NOTE: the cookie storage model specification states that if both expires and maxAge are set,
    // then maxAge takes precedence, but it is possible not all clients by obey this, so if both are set,
    // they should point to the same date and time.
    //
    // The following sets the cookie for 80 days (= 60 * 60 * 24 * 80 = 6912000 sec)
    maxAge: 60 * 60 * 24 * 80,
    // maxAge: 7200000,

    // Specifies the boolean or string to be the value for the SameSite Set-Cookie attribute.
    // true will set the SameSite attribute to Strict for strict same site enforcement.
    // false will not set the SameSite attribute.
    // 'lax' will set the SameSite attribute to Lax for lax same site enforcement.
    // 'none' will set the SameSite attribute to None for an explicit cross-site cookie.
    // 'strict' will set the SameSite attribute to Strict for strict same site enforcement.
    //
    // More information about the different enforcement levels can be found in the specification:
    // https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-03#section-4.1.2.7
    sameSite: true,
  };
}

function defaultErrorNotFoundHandler() {
  return (req, res, next) => {
    const error = new Error('Not Found');
    error.status = HttpStatus.statusNotFound;
    next(error);
  };
}

function defaultErrorHandler(expressApp) {
  // eslint-disable-next-line no-unused-vars
  return (error, req, res, next) => {

    expressApp.logError(error.message, error);
    res.status(error.status || HttpStatus.statusServerError);

    const returnValue = {
      message: error.message,
    };

    if (!isProduction) {
      returnValue.error = error;
    }

    // isApi ? res.json(returnValue) : res.render('error', returnValue);
    res.json(returnValue);
  };
}

function initializeApplication(expressApp) {
  // Add middleware
  expressApp.middleware.forEach((middleware) => {
    expressApp.app.use(middleware);
  });

  // Add routers
  expressApp.routers.forEach((routerInfo) => {
    if (!routerInfo.middleware) expressApp.app.use(routerInfo.path, ...routerInfo.router);
    else expressApp.app.use(routerInfo.path, ...routerInfo.middleware, routerInfo.router);
  });

  // Errors/NotFound
  expressApp.app.use(expressApp.errorNotFoundHandler);
  expressApp.app.use(expressApp.errorHandler);
}
