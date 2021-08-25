// Express
exports.ExpressApplication = require('./lib/express/expressApplication');
exports.RouterInfo = require('./lib/express/RouterInfo');
exports.ControllerBase = require('./lib/express/controllers/controllerBase');
exports.MongoStore = require('./lib/tools/mongoStore');

// Validators
exports.FormFieldValidator = require('./lib/express/validators/formFieldValidator');

// Security
const { PasswordService, EncryptionService, JwtService } = require('@1onlinesolution/dws-crypto');
exports.PasswordService = PasswordService;
exports.EncryptionService = EncryptionService;
exports.JwtService = JwtService;

// Tools
const { DateTimeUtils, Converter, Validity } = require('@1onlinesolution/dws-utils');
exports.DateTimeUtils = DateTimeUtils;
exports.Converter = Converter;
exports.Validity = Validity;

// Session
exports.session = require('@1onlinesolution/dws-session');

// Log
const { Logger, consoleOptions, fileOptions, mongoOptions } = require('@1onlinesolution/dws-log');
exports.Logger = Logger;
exports.consoleOptions = consoleOptions;
exports.fileOptions = fileOptions;
exports.mongoOptions = mongoOptions;

// Mail
const { EmailService } = require('@1onlinesolution/dws-mail');
exports.EmailService = EmailService;

// Http
const { ipAddress, HttpStatus, HttpStatusResponse } = require('@1onlinesolution/dws-http');
exports.ipAddress = ipAddress;
exports.HttpStatus = HttpStatus;
exports.HttpStatusResponse = HttpStatusResponse;

// Models
exports.Address = require('./lib/models/documents/sso/address');
exports.UserStatistics = require('./lib/models/documents/sso/userStatistics');
exports.UserRole = require('./lib/models/documents/sso/userRole');
exports.User = require('./lib/models/documents/sso/user');
exports.UserLogin = require('./lib/models/documents/sso/userLogin');
exports.ApiClientApplication = require('./lib/models/documents/sso/apiClientApplication');
exports.CreateUserParameters = require('./lib/models/documents/sso/requestParams/createUserParameters');
exports.UpdateUserParameters = require('./lib/models/documents/sso/requestParams/updateUserParameters');
exports.CreateUserAddressParameters = require('./lib/models/documents/sso/requestParams/createUserAddressParameters');
exports.DeleteUserAddressParameters = require('./lib/models/documents/sso/requestParams/deleteUserAddressParameters');
exports.EmailUserParameters = require('./lib/models/documents/sso/requestParams/emailUserParameters');
exports.EmailUserDataParameters = require('./lib/models/documents/sso/requestParams/emailUserDataParameters');
exports.LoginUserParameters = require('./lib/models/documents/sso/requestParams/loginUserParameters');
exports.VerifyUserTokenParameters = require('./lib/models/documents/sso/requestParams/verifyUserTokenParameters');
exports.ForgotPasswordParameters = require('./lib/models/documents/sso/requestParams/forgotPasswordParameters');
exports.AutoResetPasswordParameters = require('./lib/models/documents/sso/requestParams/autoResetPasswordParameters');
exports.ResetPasswordParameters = require('./lib/models/documents/sso/requestParams/resetPasswordParameters');
exports.CreateApiClientApplicationParameters = require('./lib/models/documents/sso/requestParams/createApiClientApplicationParameters');
exports.CreateApiClientApplicationAuthorizationCodeParameters = require('./lib/models/documents/sso/requestParams/createApiClientApplicationAuthorizationCodeParameters');
exports.AuthorizeApplicationParameters = require('./lib/models/documents/sso/requestParams/authorizeApiClientApplicationParameters');
exports.PaymentStatus = require('./lib/models/documents/orderPipeline/paymentStatus');
exports.OrderStatus = require('./lib/models/documents/orderPipeline/orderStatus');
exports.OrderTerm = require('./lib/models/documents/orderPipeline/orderTerm');
exports.Customer = require('./lib/models/documents/orderPipeline/customer');
exports.ProductFeature = require('./lib/models/documents/orderPipeline/productFeature');
exports.Product = require('./lib/models/documents/orderPipeline/product');
exports.OrderItem = require('./lib/models/documents/orderPipeline/orderItem');
exports.Order = require('./lib/models/documents/orderPipeline/order');
exports.CreateProductParameters = require('./lib/models/documents/orderPipeline/requestparams/createProductParameters');
exports.UpdateProductParameters = require('./lib/models/documents/orderPipeline/requestparams/updateProductParameters');

// Engine
exports.DataType = require('./lib/models/documents/dataTypes');
exports.MaterialTypes = require('./lib/models/documents/apps/engine/materialTypes');
exports.ElementTypes = require('./lib/models/documents/apps/engine/elementTypes');
exports.PropertyTypes = require('./lib/models/documents/apps/engine/propertyTypes');
exports.ElasticityConditions = require('./lib/models/documents/apps/engine/elasticityConditions');
exports.StressReferenceSystem = require('./lib/models/documents/apps/engine/stressReferenceSystem');
exports.Property = require('./lib/models/documents/apps/engine/property');
exports.ElementGroup = require('./lib/models/documents/apps/engine/elementGroup');
exports.Node = require('./lib/models/documents/apps/engine/node');
exports.Element = require('./lib/models/documents/apps/engine/element');
exports.defaultDatabaseProperties = require('./lib/models/documents/apps/engine/defaultDatabaseProperties');
exports.CreateProjectParameters = require('./lib/models/documents/apps/requestParams/createProjectParameters');
exports.ProjectStatus = require('./lib/models/documents/apps/projectStatus');
exports.ProjectData = require('./lib/models/documents/apps/projectData');
exports.Project = require('./lib/models/documents/apps/project');
exports.DomainOptions = require('./lib/models/documents/apps/engine/domainOptions');

// Database
const { ObjectId, MongoConnection, MongoDatabase, MongoCollection } = require('@1onlinesolution/dws-mongodb');
exports.ObjectId = ObjectId;
exports.MongoConnection = MongoConnection;
exports.MongoDatabase = MongoDatabase;
exports.MongoCollection = MongoCollection;

exports.DamianosDatabase = require('./lib/db/damianosDb/damianosDatabase');
exports.StructureDatabase = require('./lib/db/engine/structureDatabase');
