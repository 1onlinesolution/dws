const ObjectId = require('mongodb').ObjectID;
const PasswordService = require('../../security/passwordService');
const EncryptionService = require('../../security/encryptionService');
const JwtService = require('../../security/jwtService');
const Converter = require('../../tools/converter');
const MongoCollection = require('../mongodb/mongoCollection');
const MongoConnection = require('../mongodb/mongoConnection');
const MongoDatabase = require('../mongodb/mongoDatabase');
const User = require('../../models/documents/sso/user');
const UserLogin = require('../../models/documents/sso/userLogin');
const UserRole = require('../../models/documents/sso/userRole');
const Validity = require('../../tools/validity');
const BlackListedRefreshToken = require('../../models/documents/sso/blackListedRefreshToken');
const Product = require('../../models/documents/orderPipeline/product');
const EmailNotSent = require('../../models/documents/sso/emailNotSent');
const ApiClient = require('../../models/documents/sso/apiClient');
const ApiClientApplication = require('../../models/documents/sso/apiClientApplication');
const CreateUserParameters = require('../../models/documents/sso/requestParams/createUserParameters');
const UpdateUserParameters = require('../../models/documents/sso/requestParams/updateUserParameters');
const LoginUserParameters = require('../../models/documents/sso/requestParams/loginUserParameters');
const CreateApiClientParameters = require('../../models/documents/sso/requestParams/createApiClientParameters');
const CreateApiClientApplicationParameters = require('../../models/documents/sso/requestParams/createApiClientApplicationParameters');
const AuthorizeApplicationParameters = require('../../models/documents/sso/requestParams/authorizeApplicationParameters');
const RefreshApplicationAccessTokenParameters = require('../../models/documents/sso/requestParams/refreshApplicationAccessTokenParameters');
const CreateApiClientApplicationAuthorizationCodeParameters = require('../../models/documents/sso/requestParams/createApiClientApplicationAuthorizationCodeParameters');
const CreateProductParameters = require('../../models/documents/orderPipeline/requestparams/createProductParameters');
const UpdateProductParameters = require('../../models/documents/orderPipeline/requestparams/updateProductParameters');
const EmailParameters = require('../../models/documents/sso/requestParams/emailParameters');
const EmailUserParameters = require('../../models/documents/sso/requestParams/emailUserParameters');
const EmailUserDataParameters = require('../../models/documents/sso/requestParams/emailUserDataParameters');
const VerifyUserTokenParameters = require('../../models/documents/sso/requestParams/verifyUserTokenParameters');
const ForgotPasswordParameters = require('../../models/documents/sso/requestParams/forgotPasswordParameters');
const AutoResetPasswordParameters = require('../../models/documents/sso/requestParams/autoResetPasswordParameters');
const ResetPasswordParameters = require('../../models/documents/sso/requestParams/resetPasswordParameters');
const CreateEmailNotSentParameters = require('../../models/documents/sso/requestParams/createEmailNotSentParameters');
const DateTimeUtils = require('../../tools/dateTimeUtils');
const sendMail = require('../../email/sendMail');

const CreateUserLoginParameters = require('../../models/documents/sso/requestParams/createUserLoginParameters');
const CreateBlackListedRefreshTokenParameters = require('../../models/documents/sso/requestParams/createBlackListedRefreshTokenParameters');

class DamianosDatabase extends MongoDatabase {
  constructor({
    connection, name, logger, encryptionKey = process.env.ENCRYPTION_KEY,
    jwt_algorithm = process.env.JWT_ALGORITHM,
    jwt_accessTokenSecretKey = process.env.JWT_ACCESS_TOKEN_SECRET_KEY,
    jwt_refreshTokenSecretKey = process.env.JWT_REFRESH_TOKEN_SECRET_KEY,
    jwt_accessTokenExpiresIn = process.env.JWT_EXPIRATION_ACCESS_TOKEN,
    jwt_refreshTokenExpiresIn = process.env.JWT_EXPIRATION_REFRESH_TOKEN,
  }) {
    super(connection, name);
    if (!logger) throw new Error('invalid logger');
    if (!encryptionKey) throw new Error('invalid encryption key');
    if (!jwt_algorithm) throw new Error('invalid JWT algorithm');
    if (!jwt_accessTokenSecretKey) throw new Error('invalid JWT access token secret key');
    if (!jwt_refreshTokenSecretKey) throw new Error('invalid JWT refresh token secret key');
    if (!jwt_accessTokenExpiresIn) throw new Error('invalid JWT access token expiration period');
    if (!jwt_refreshTokenExpiresIn) throw new Error('invalid JWT refresh token expiration period');

    this._users = new MongoCollection(this, 'users');
    this._userLogins = new MongoCollection(this, 'userLogins');
    this._blackListedRefreshTokens = new MongoCollection(this, 'blackListedRefreshTokens');
    this._products = new MongoCollection(this, 'products');
    this._apiClients = new MongoCollection(this, 'apiClients');
    this._emailsNotSent = new MongoCollection(this, 'emailsNotSent');
    this._logger = logger;

    // Encryption
    this.encryptionKey = encryptionKey;

    // JWT handling
    this.jwt_algorithm = jwt_algorithm;
    this.jwt_accessTokenSecretKey = jwt_accessTokenSecretKey;
    this.jwt_refreshTokenSecretKey = jwt_refreshTokenSecretKey;
    this.jwt_accessTokenExpiresIn = Converter.toSeconds(jwt_accessTokenExpiresIn);
    this.jwt_refreshTokenExpiresIn = Converter.toSeconds(jwt_refreshTokenExpiresIn);

    return this;
  }

  getJwtService() {
    return new JwtService({
      algorithm: this.jwt_algorithm,
      accessTokenSecretKey: this.jwt_accessTokenSecretKey,
      expiresIn: this.jwt_accessTokenExpiresIn,
      refreshTokenSecretKey: this.jwt_refreshTokenSecretKey,
      refreshExpiresIn: this.jwt_refreshTokenExpiresIn,
    });
  }

  // Accessor Properties
  get users() {
    return this._users;
  }

  get userLogins() {
    return this._userLogins;
  }

  get blackListedRefreshTokens() {
    return this._blackListedRefreshTokens;
  }

  get products() {
    return this._products;
  }

  get apiClients() {
    return this._apiClients;
  }

  get emailsNotSent() {
    return this._emailsNotSent;
  }

  get logger() {
    return this._logger;
  }

  static async createDatabase({
    name,
    logger,
    connectionString,
    encryptionKey = process.env.ENCRYPTION_KEY,
    jwt_algorithm = process.env.JWT_ALGORITHM,
    jwt_accessTokenSecretKey = process.env.JWT_ACCESS_TOKEN_SECRET_KEY,
    jwt_refreshTokenSecretKey = process.env.JWT_REFRESH_TOKEN_SECRET_KEY,
    jwt_accessTokenExpiresIn = process.env.JWT_EXPIRATION_ACCESS_TOKEN,
    jwt_refreshTokenExpiresIn = process.env.JWT_EXPIRATION_REFRESH_TOKEN,
    connectionOptions = {
      useUnifiedTopology: true,
    },
  } = {}) {
    try {
      const connection = new MongoConnection(connectionString, connectionOptions);
      await connection.connect();
      const database = new DamianosDatabase({
        connection, name, logger,
        encryptionKey,
        jwt_algorithm,
        jwt_accessTokenSecretKey,
        jwt_refreshTokenSecretKey,
        jwt_accessTokenExpiresIn,
        jwt_refreshTokenExpiresIn,
      });
      await database.createIndex();
      return database;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  now() {
    return DateTimeUtils.currentUtcDate();
  }

  async createIndex() {
    await this._users.createIndexes(User.indexMap);
    await this._userLogins.createIndexes(UserLogin.indexMap);
    await this._blackListedRefreshTokens.createIndexes(BlackListedRefreshToken.indexMap);
    await this._products.createIndexes(Product.indexMap);
    await this._apiClients.createIndexes(ApiClient.indexMap);
    await this._emailsNotSent.createIndexes(EmailNotSent.indexMap);
  }

  async statistics() {
    return await this.database.command({ dbStats: 1 });
  }

  isUserVerified(user) {
    return user.verified;
  }

  hasVerificationToken(user) {
    return user.verification_token;
  }

  async checkPassword(email, password) {
    try {
      if (!email) return Promise.reject(new Error('invalid email'));
      if (!password) return Promise.reject(new Error('invalid password'));
      const user = await this.findUserByEmail(email);
      if (!user) return false;
      return await PasswordService.checkPassword(password, user.password);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async findUser(filter = {}) {
    try {
      return await this.users.find(filter);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  // id => string
  async findUserById(id) {
    if (!id) return Promise.reject(new Error('invalid user identifier'));
    try {
      const document = await this.users.findOne({ _id: ObjectId(id) });
      if (document) return new User(document);
      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async findUserByEmail(email) {
    if (!email) return Promise.reject(new Error('invalid email'));
    try {
      const document = await this.users.findOne({ email: email });
      if (document) return new User(document);
      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async findUserByUserName(userName) {
    if (!userName) return Promise.reject(new Error('invalid user name'));
    try {
      const document = await this.users.findOne({ userName: userName });
      if (document) return new User(document);
      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async findUserLogin(filter) {
    filter = filter || {};

    try {
      return await this.userLogins.find(filter);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async findUserLoginByEmail(email) {
    if (!email) return Promise.reject(new Error('invalid user email address'));
    return await this.userLogins.find({ email: email });
  }

  async findApplicationByClientId(clientId) {
    if (!clientId) return Promise.reject(new Error('invalid client identifier'));

    const apiClient = await this.apiClients.findOne({ 'applications.clientId': clientId });
    if (apiClient) {
      const { applications } = apiClient;
      return applications.find((item) => item.clientId === clientId);
    }

    return null;
  }

  async findUserApplications() {
    // TODO: To be reviewed!!!
    // https://docs.mongodb.com/manual/reference/method/db.collection.aggregate/
    // https://docs.mongodb.com/manual/reference/operator/aggregation/lookup/#use-lookup-with-mergeobjects
    // https://docs.mongodb.com/manual/tutorial/aggregation-zip-code-data-set/
    // https://stackoverflow.com/a/48631398
    // https://www.djamware.com/post/5d7f3ab0290dd8b012d95a9d/mongodb-tutorial-aggregate-method-example
    // https://dzone.com/articles/three-approaches-to-creating-a-sql-join-equivalent
    try {
      const apps = await this.users.aggregate([
        {
          $lookup: {
            from: this.apiClients.collectionName,
            localField: 'applications',
            foreignField: 'applications.clientId',
            as: 'app_info',
          },
        },
        {
          $replaceRoot: { newRoot: { $mergeObjects: [{ $arrayElemAt: ['$fromItems', 0] }, '$$ROOT'] } },
        },
        { $project: { fromItems: 0 } },
      ]);

      // add an array of application names to hold the data
      const application_names = [];
      await apps.forEach(
        (doc) => {
          doc.app_info.forEach((item) => {
            item.applications.forEach((app) => {
              // found an application, let's get the name
              application_names.push(app.applicationName);
            });
          });
        } /*, err => {
          if (err) ...
        }*/,
      );

      // return the app names
      return application_names;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async createUser(createUserParameters) {
    const error = CreateUserParameters.checkForError(createUserParameters);
    if (error) return Promise.reject(error);

    try {
      let user = await this.findUserByEmail(createUserParameters.email);
      if (user) return Promise.reject(new Error('email already exists'));

      const hash = await PasswordService.hashPassword(createUserParameters.password);
      const verification_token = await PasswordService.randomBytesAsToken(32);
      user = new User({
        firstName: createUserParameters.firstName,
        lastName: createUserParameters.lastName,
        userName: createUserParameters.userName,
        email: createUserParameters.email,
        autoVerify: createUserParameters.autoVerify,
        newsletter: createUserParameters.newsletter,
        applications: [createUserParameters.application],
        application_active: createUserParameters.application,
        password: hash,
        verification_token,
      });

      const userId = await this.users.insertOneWithWriteConcern(user);
      if (userId) {
        user._id = userId;
        delete user.password;

        const application = await this.findApplicationByClientId(createUserParameters.application);
        if (!application) return Promise.reject(new Error('invalid application'));
        const { applicationName } = application;
        if (user.autoVerify) {
          // Email user the reset-password link
          await this.emailUserVerificationInfo(user, createUserParameters.emailParameters, applicationName);
        } else {
          await this.emailAdminNewUserRegistered(user, createUserParameters.emailParameters, applicationName);
        }

        return user;
      }

      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async emailAdminNewUserRegistered(user, emailParameters, applicationName) {
    if (!user) return Promise.reject(new Error('invalid user information'));
    if (user.verified) return Promise.reject(new Error('user is already verified'));
    const error = EmailParameters.checkForError(emailParameters);
    if (error) return Promise.reject(error);

    try {
      // Email user the reset-password link
      const emailUserDataParameters = new EmailUserDataParameters({
        user: User.getPayloadForSession(user),
        data: {
          applicationName: applicationName,
        },
        ...emailParameters,
      });

      await this.email(emailUserDataParameters, DamianosDatabase.createNewUserCreatedEmailMessage);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async emailUserVerificationInfo(user, emailParameters, applicationName) {
    if (!user) return Promise.reject(new Error('invalid user information'));
    if (user.verified) return Promise.reject(new Error('user is already verified'));
    const error = EmailParameters.checkForError(emailParameters);
    if (error) return Promise.reject(error);

    try {
      // Email user the reset-password link
      const encryptionService = new EncryptionService({ encryptionKey: this.encryptionKey });
      const afterTwoHoursUtc = this.now();
      afterTwoHoursUtc.setTime(afterTwoHoursUtc.getTime() + 2 * 60 * 60 * 1000);
      const emailUserDataParameters = new EmailUserDataParameters({
        user: User.getPayloadForSession(user),
        data: {
          token: await encryptionService.encryptObjectCompact({
            email: user.email,
            expirationDate: afterTwoHoursUtc,
          }),
          applicationName: applicationName,
        },
        ...emailParameters,
      });

      await this.email(emailUserDataParameters, DamianosDatabase.createVerificationCodeEmailMessage);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async loginUser(loginUserParameters) {
    try {
      const { user, old_jwt_refresh_token } = await this.loginVerifiedUser(loginUserParameters);
      if (!loginUserParameters.issueJwtTokens) {
        const application = await this.findApplicationByClientId(user.application_active);
        if (!application) return Promise.reject(new Error('invalid application'));
        const { applicationName } = application;

        // Email user login attempt
        const encryptionService = new EncryptionService({ encryptionKey: this.encryptionKey });
        const afterTwoHoursUtc = this.now();
        afterTwoHoursUtc.setTime(afterTwoHoursUtc.getTime() + 2 * 60 * 60 * 1000);
        const emailUserDataParameters = new EmailUserDataParameters({
          user: User.getPayloadForSession(user),
          data: {
            token: await encryptionService.encryptObjectCompact({
              email: user.email,
              expirationDate: afterTwoHoursUtc,
            }),
            applicationName,
          },
          ...loginUserParameters,
        });
        await this.email(emailUserDataParameters, DamianosDatabase.createLoginAttemptEmailMessage);
      }

      const loginIsAllowed = user && user.verified;
      if (loginIsAllowed) {
        // Join user with apiClientApplication to fetch the app names
        // user.application_names = await this.findUserApplications(user);

        if (!(await this.createUserLoginRecord(new CreateUserLoginParameters({ ...loginUserParameters })))) return null;

        if (old_jwt_refresh_token) {
          await this.createBlackListedRefreshToken(
            new CreateBlackListedRefreshTokenParameters({
              ip: loginUserParameters.ip,
              token: old_jwt_refresh_token,
            }),
          );
        }
        return user;
      }

      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async loginVerifiedUser(loginUserParameters) {
    const error = LoginUserParameters.checkForError(loginUserParameters);
    if (error) return Promise.reject(error);

    try {
      // loginUserParameters.email can hold either the user email OR the user name
      const emailOrUserName = loginUserParameters.email;
      const user = emailOrUserName.includes('@') ? await this.findUserByEmail(emailOrUserName) : await this.findUserByUserName(emailOrUserName);
      if (!user) return Promise.reject(new Error('invalid email/userName and/or password'));
      if (!user.verified) return Promise.reject(new Error('you need to verify your email before you can sign in'));

      if (!(await DamianosDatabase.checkUserPassword(user, loginUserParameters.password))) {
        return Promise.reject(new Error('invalid email and/or password'));
      }

      const old_jwt_refresh_token = user.jwt_refresh_token;

      const { accessToken, refreshToken } = await user.createVerifiedUserTokens();
      user.jwt_access_token = accessToken;
      user.jwt_refresh_token = refreshToken;

      // We have found a user, if we are here...
      if (!loginUserParameters.issueJwtTokens) {
        // Update apps if the user is not actually logged in.
        // If we simply want to generate new refresh JWT token, skip this bit.
        if (!user.applications.includes(loginUserParameters.application)) {
          user.applications.push(loginUserParameters.application);
        }
      }

      // Update the database
      const nowUtc = this.now();
      let updateOptions;
      if (!loginUserParameters.issueJwtTokens) {
        updateOptions = {
          applications: user.applications,
          application_active: loginUserParameters.application,
          jwt_access_token: user.jwt_access_token,
          jwt_refresh_token: user.jwt_refresh_token,
          'stats.lastLoggedInAt': nowUtc,
          'stats.countLogIns': 1 + user.stats.countLogIns,
          createdRefreshTokenAt: nowUtc,
          modifiedAt: nowUtc,
        };
      } else {
        updateOptions = {
          jwt_access_token: user.jwt_access_token,
          jwt_refresh_token: user.jwt_refresh_token,
          'stats.lastLoggedInAt': nowUtc,
          'stats.countJwtGenerations': 1 + user.stats.countJwtGenerations,
          createdRefreshTokenAt: nowUtc,
          modifiedAt: nowUtc,
        };
      }
      await this.updateUserCore(User.id(user), updateOptions);
      delete user.password;
      return { user, old_jwt_refresh_token };
    } catch (err) {
      return Promise.reject(err);
    }
  }

  static isUserAdmin(user) {
    return user && user.roles && Validity.isArray(user.roles) && user.roles.includes(UserRole.admin);
  }

  static async checkUserPassword(user, password) {
    if (!password) return Promise.reject(new Error('invalid plain password'));
    return await PasswordService.checkPassword(password, user.password);
  }

  async updateUser(updateUserParameters) {
    const error = UpdateUserParameters.checkForError(updateUserParameters);
    if (error) return Promise.reject(error);
    const { user_id, firstName, lastName, newsletter } = updateUserParameters;
    try {
      const user = await this.findUserById(user_id);
      if (!user) return Promise.reject(new Error('invalid user'));
      if (!user.verified) return Promise.reject(new Error('user is not verified'));

      const updateOptions = {
        firstName,
        lastName,
        newsletter: newsletter,
        modifiedAt: this.now(),
      };

      return await this.updateUserCore(user_id, updateOptions);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async updateUserCore(user_id, updateOptions) {
    if (!user_id) return Promise.reject(new Error('invalid user identifier'));
    if (!updateOptions) return Promise.reject(new Error('invalid user update options'));

    // Update the database
    return await this.users.updateOneWithWriteConcern({ _id: ObjectId(user_id) }, { $set: updateOptions });
  }

  async updateUserApps(user, application) {
    if (user.applications.includes(application)) return;

    if (!user.applications.includes(application)) {
      user.applications.push(application);
    }
    user.application_active = application;

    // Update the database
    return await this.updateUserCore(User.id(user), {
      applications: user.applications,
      application_active: application,
      modifiedAt: this.now(),
    });
  }

  async createUserLoginRecord(createUserLoginParameters) {
    try {
      const userLogin = new UserLogin(createUserLoginParameters);
      const userLoginId = await this.userLogins.insertOneWithWriteConcern(userLogin);
      if (userLoginId) {
        userLogin._id = userLoginId;
      }
      return userLoginId ? userLogin : null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async createBlackListedRefreshToken(createBlackListedRefreshTokenParameters) {
    try {
      const blackListedRefreshToken = new BlackListedRefreshToken(createBlackListedRefreshTokenParameters);
      const blackListedRefreshTokenId = await this.blackListedRefreshTokens.insertOneWithWriteConcern(blackListedRefreshToken);
      if (blackListedRefreshTokenId) {
        blackListedRefreshToken._id = blackListedRefreshTokenId;
        return blackListedRefreshToken;
      }
      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async logoutUser(user_id) {
    if (!user_id) return Promise.reject(new Error('invalid user'));

    try {
      const user = await this.findUserById(user_id);
      if (!user) return Promise.reject(new Error('invalid user'));
      if (!user.jwt_access_token && !user.jwt_refresh_token) return;

      // We have found a user, if we are here...
      // Update the database - remove tokens
      const nowUtc = this.now();
      await this.updateUserCore(User.id(user), {
        jwt_access_token: null,
        jwt_refresh_token: null,
        createdRefreshTokenAt: null,
        modifiedAt: nowUtc,
      });
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async refreshAccessToken(user_id) {
    if (!user_id) return Promise.reject(new Error('invalid user identifier'));

    try {
      const user = await this.findUserById(user_id);
      if (!user) return Promise.reject(new Error('invalid user'));
      if (!user.verified) return Promise.reject(new Error('unconfirmed user'));

      const jwtService = this.getJwtService();
      if (!jwtService) return Promise.reject(new Error('invalid JWT service'));
      if (!(await jwtService.verifyRefreshToken(user.jwt_refresh_token))) return Promise.reject(new Error('invalid user refresh token'));

      // If we are here, we have a user and authentication was successful.
      const payload = User.getPayloadForToken(user);
      if (!payload) return Promise.reject(new Error('cannot get user payload'));

      const accessToken = await jwtService.createAccessToken(payload);

      // To verify access token use:
      // const result = await jwtService.verifyAccessToken(accessToken);

      // Update the database
      const nowUtc = this.now();
      const updated = await this.updateUserCore(User.id(user), {
        jwt_access_token: accessToken,
        modifiedAt: nowUtc,
      });

      // return the new access token
      return updated ? accessToken : null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async changeUserPassword(email, newPassword) {
    if (!newPassword || newPassword.length < 8) return Promise.reject(new Error('invalid proposed password'));

    try {
      let user = await this.findUserByEmail(email);
      if (!user) return Promise.reject(new Error('cannot find user'));
      const hash = await PasswordService.hashPassword(newPassword);
      const update = {
        $set: {
          password: hash,
          modifiedAt: this.now(),
        },
      };
      return await this.updateOneWithWriteConcern({ email: email }, update);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async emailConfirmation(emailUserParameters) {
    const error = EmailUserParameters.checkForError(emailUserParameters);
    if (error) return Promise.reject(error);
    if (!emailUserParameters.user.requiresVerification) return Promise.reject(new Error('user is verified'));

    try {
      const application = await this.findApplicationByClientId(emailUserParameters.user.application_active);
      if (!application) return Promise.reject(new Error('invalid application'));
      const { applicationName } = application;

      const afterTwoHoursUtc = this.now();
      const encryptionService = new EncryptionService({ encryptionKey: this.encryptionKey });
      afterTwoHoursUtc.setTime(afterTwoHoursUtc.getTime() + 2 * 60 * 60 * 1000);
      const { user, ip, host } = emailUserParameters;
      const emailUserDataParameters = new EmailUserDataParameters({
        data: {
          token: await encryptionService.encryptObjectCompact({
            email: emailUserParameters.user.email,
            expirationDate: afterTwoHoursUtc,
          }),
        },
        applicationName,
        user: User.getPayloadForSession(user),
        ip,
        host,
      });

      await this.email(emailUserDataParameters, DamianosDatabase.createVerificationCodeEmailMessage);
      return true;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async verifyAccount(verifyUserTokenParameters) {
    const error = VerifyUserTokenParameters.checkForError(verifyUserTokenParameters);
    if (error) return Promise.reject(error);

    try {
      const { token } = verifyUserTokenParameters;

      const encryptionService = new EncryptionService({ encryptionKey: this.encryptionKey });
      const data = encryptionService.decryptObjectCompact(token);
      const { email, expirationDate } = data;
      const nowUtc = this.now();
      if (nowUtc > expirationDate) return Promise.reject(new Error('token has expired'));

      const user = await this.findUserByEmail(email);
      if (!user || !user.requiresVerification) return Promise.reject(new Error('invalid user'));

      // Update the database
      const verified = await this.updateUserCore(User.id(user), {
        verified: true,
        verification_token: null,
        modifiedAt: this.now(),
      });

      if (verified) {
        // Update local object
        user.verified = true;
        user.verification_token = null;

        const application = await this.findApplicationByClientId(user.application_active);
        if (!application) return Promise.reject(new Error('invalid application'));
        const { applicationName } = application;

        // Email user confirmation
        const emailUserDataParameters = new EmailUserDataParameters({
          user: User.getPayloadForSession(user),
          data: {
            applicationName,
          },
          ...verifyUserTokenParameters,
        });
        await this.email(emailUserDataParameters, DamianosDatabase.createVerificationConfirmationEmailMessage);
      }
      return verified;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async forgotPassword(forgotPasswordParameters) {
    const error = ForgotPasswordParameters.checkForError(forgotPasswordParameters);
    if (error) return Promise.reject(error);
    const { email } = forgotPasswordParameters;

    try {
      const user = await this.findUserByEmail(email);
      if (!user || user.requiresVerification) return Promise.reject(new Error('invalid user'));

      // Email user the reset-password link
      const application = await this.findApplicationByClientId(user.application_active);
      if (!application) return Promise.reject(new Error('invalid application'));
      const { applicationName } = application;

      const afterTwoHoursUtc = this.now();
      const encryptionService = new EncryptionService({ encryptionKey: this.encryptionKey });
      afterTwoHoursUtc.setTime(afterTwoHoursUtc.getTime() + 2 * 60 * 60 * 1000);
      const emailUserDataParameters = new EmailUserDataParameters({
        user: User.getPayloadForSession(user),
        data: {
          token: await encryptionService.encryptObjectCompact({
            email,
            expirationDate: afterTwoHoursUtc,
          }),
          applicationName,
        },
        ...forgotPasswordParameters,
      });

      await this.email(emailUserDataParameters, DamianosDatabase.createPasswordResetEmailMessage);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async autoResetPassword(autoResetPasswordParameters) {
    const error = AutoResetPasswordParameters.checkForError(autoResetPasswordParameters);
    if (error) return Promise.reject(error);
    const { token, password } = autoResetPasswordParameters;

    try {
      const encryptionService = new EncryptionService({ encryptionKey: this.encryptionKey });
      const data = encryptionService.decryptObjectCompact(token);
      const { email, expirationDate } = data;
      const nowUtc = this.now();
      if (nowUtc > expirationDate) return Promise.reject(new Error('token has expired'));

      const user = await this.findUserByEmail(email);
      if (!user || user.requiresVerification) return Promise.reject(new Error('invalid user'));

      // Update the database
      const changed = await this.updateUserCore(User.id(user), {
        password: await PasswordService.hashPassword(password),
        modifiedAt: this.now(),
      });

      if (changed) {
        const application = await this.findApplicationByClientId(user.application_active);
        if (!application) return Promise.reject(new Error('invalid application'));
        const { applicationName } = application;

        // Email user the reset-password link
        const emailUserDataParameters = new EmailUserDataParameters({
          user: User.getPayloadForSession(user),
          data: {
            applicationName,
          },
          ...autoResetPasswordParameters,
        });
        await this.email(emailUserDataParameters, DamianosDatabase.createPasswordResetConfirmationEmailMessage);
      }
      return changed;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async resetPassword(resetPasswordParameters) {
    const error = ResetPasswordParameters.checkForError(resetPasswordParameters);
    if (error) return Promise.reject(error);
    const { user, password } = resetPasswordParameters;
    if (!user || !user.verified) return Promise.reject(new Error('invalid or unconfirmed user'));

    try {
      // Update the database
      const changed = await this.updateUserCore(User.id(user), {
        password: await PasswordService.hashPassword(password),
        modifiedAt: this.now(),
      });

      if (changed) {
        const application = await this.findApplicationByClientId(user.application_active);
        if (!application) return Promise.reject(new Error('invalid application'));
        const { applicationName } = application;

        // Email user the reset-password link
        const emailUserDataParameters = new EmailUserDataParameters({
          user: User.getPayloadForSession(user),
          data: {
            applicationName,
          },
          ...resetPasswordParameters,
        });
        await this.email(emailUserDataParameters, DamianosDatabase.createPasswordResetConfirmationEmailMessage);
        return true;
      }
      return false;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  // === Products ===
  //
  async findProduct(filter = {}) {
    try {
      return await this.products.find(filter);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  // id => string
  async findProductById(id) {
    if (!id) return Promise.reject(new Error('invalid product identifier'));
    return await this.products.findOne({ _id: ObjectId(id) });
  }

  async findProductByName(name) {
    if (!name) return Promise.reject(new Error('invalid product name'));
    return await this.products.findOne({ name: name });
  }

  async updateProductCore(product, updateOptions) {
    if (!product || !product._id) return Promise.reject(new Error('invalid product information'));
    if (!updateOptions) return Promise.reject(new Error('invalid product update options'));

    // Update the database
    return await this.products.updateOneWithWriteConcern({ _id: ObjectId(product._id) }, { $set: updateOptions });
  }

  async createProduct(createProductParameters) {
    const error = CreateProductParameters.checkForError(createProductParameters);
    if (error) return Promise.reject(error);

    try {
      let product = await this.findProductByName(createProductParameters.name);
      if (product) return Promise.reject(new Error('product name already exists'));

      product = new Product({
        name: createProductParameters.name,
        price: createProductParameters.price,
        description: createProductParameters.description,
        features: createProductParameters.features,
        category: createProductParameters.category,
        locked: createProductParameters.locked,
      });

      const product_id = await this.products.insertOneWithWriteConcern(product);
      if (product_id) {
        product._id = product_id;
        return product;
      }

      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async updateProduct(updateProductParameters) {
    const error = UpdateProductParameters.checkForError(updateProductParameters);
    if (error) return Promise.reject(error);

    const { _id, name, price, description, features, category, locked } = updateProductParameters;
    try {
      let product = await this.findProductById(_id);
      if (!product) return Promise.reject(new Error('product does not exist in database'));

      const nowUtc = this.now();
      const updateOptions = {
        name,
        price,
        description,
        features,
        category,
        locked,
        modifiedAt: nowUtc,
      };

      // Update the database
      return await this.updateProductCore(product, updateOptions);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async deleteProduct(productId) {
    if (!productId) return Promise.reject(new Error('invalid product id'));
    return await this.products.deleteOne({ _id: ObjectId(productId) });
  }

  // === BlackListedRefreshTokens ===
  //
  async findBlackListedRefreshToken(filter = {}) {
    try {
      return await this.blackListedRefreshTokens.find(filter);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  // === ApiClient ===
  //

  async findApiClientByEmail(email) {
    if (!email) return Promise.reject(new Error('invalid email address'));

    try {
      const document = await this.apiClients.findOne({ email });
      if (document) return new ApiClient(document);
      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async findApiClientByEmailAndApplicationName(email, applicationName) {
    if (!email) return Promise.reject(new Error('invalid email address'));
    if (!applicationName) return Promise.reject(new Error('invalid application name'));
    const document = await this.apiClients.findOne({ email: email, 'applications.applicationName': applicationName });
    if (document) return new ApiClient(document);
    return null;
  }

  async findApiClientByClientId(clientId) {
    if (!clientId) return Promise.reject(new Error('invalid client identifier'));
    const document = await this.apiClients.findOne({ 'applications.clientId': clientId });
    if (document) return new ApiClient(document);
    return null;
  }

  async updateApiClient(apiClient, updateOptions) {
    if (!apiClient || !apiClient._id) return Promise.reject(new Error('invalid API client'));
    if (!updateOptions) return Promise.reject(new Error('invalid API client update options'));

    // Update the database
    return await this.apiClients.updateOneWithWriteConcern({ _id: ObjectId(apiClient._id) }, { $set: updateOptions });
  }

  async createApiClient(createApiClientParameters) {
    const error = CreateApiClientParameters.checkForError(createApiClientParameters);
    if (error) return Promise.reject(error);

    try {
      let apiClient = await this.findApiClientByEmail(createApiClientParameters.email);
      if (apiClient) return Promise.reject(new Error('API client already exists'));

      apiClient = new ApiClient({ ...createApiClientParameters });
      const apiClientId = await this.apiClients.insertOneWithWriteConcern(apiClient);
      if (apiClientId) {
        apiClient._id = apiClientId;

        // if (...) {
        //   // Email client about the creation...
        // }
        return apiClient;
      }

      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async registerApiClientApplication(createApiClientApplicationParameters) {
    const error = CreateApiClientApplicationParameters.checkForError(createApiClientApplicationParameters);
    if (error) return Promise.reject(error);
    const { email, applicationName } = createApiClientApplicationParameters;

    try {
      const apiClient = await this.findApiClientByEmail(email);
      if (!apiClient) return Promise.reject(new Error('API client not found'));

      const foundApp = apiClient.applications.find((elem) => elem.applicationName === applicationName);
      if (foundApp) return Promise.reject(new Error('API client application already exists'));

      const application = await ApiClientApplication.createApiClientApplication(createApiClientApplicationParameters);
      if (application) {
        apiClient.applications.push(application);
        const nowUtc = this.now();
        const updateOptions = {
          applications: apiClient.applications,
          modifiedAt: nowUtc,
        };
        await this.updateApiClient(apiClient, updateOptions);

        return apiClient;
      }

      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async createApplicationAuthorizationCode(createApiClientApplicationAuthorizationCodeParameters) {
    const error = CreateApiClientApplicationAuthorizationCodeParameters.checkForError(createApiClientApplicationAuthorizationCodeParameters);
    if (error) return Promise.reject(error);
    const { clientId /*, redirectUrl*/ } = createApiClientApplicationAuthorizationCodeParameters;

    try {
      const apiClient = await this.findApiClientByClientId(clientId);
      if (!apiClient) return Promise.reject(new Error('invalid client identifier'));

      // We found the client
      // Now let's proceed with the application
      const appIndex = apiClient.applications.findIndex((elem) => elem.clientId === clientId);
      let code;
      if (appIndex >= 0) {
        // eslint-disable-next-line security/detect-object-injection
        const app = new ApiClientApplication(apiClient.applications[appIndex]);
        // eslint-disable-next-line security/detect-object-injection
        apiClient.applications[appIndex] = await ApiClientApplication.generateAuthorizationCode(app);
        const updateOptions = {
          applications: apiClient.applications,
          modifiedAt: this.now(),
        };
        await this.updateApiClient(apiClient, updateOptions);
        // eslint-disable-next-line security/detect-object-injection
        code = apiClient.applications[appIndex].authorizationCode;
      }

      return code;
      // const requestService = new RequestService({url: apiClient.applications[appIndex].returnUrl});
      // await requestService.post({code: code, redirectUrl: redirectUrl})
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async authorizeApplication(authorizeApplicationParameters) {
    const error = AuthorizeApplicationParameters.checkForError(authorizeApplicationParameters);
    if (error) return Promise.reject(error);
    const { authorizationCode, clientId, clientSecret } = authorizeApplicationParameters;

    try {
      const apiClient = await this.findApiClientByClientId(clientId);
      if (!apiClient) return Promise.reject(new Error('invalid client identifier'));

      // We found the client
      // Now let's proceed with the application
      const appIndex = apiClient.applications.findIndex((elem) => elem.clientId === clientId);
      // eslint-disable-next-line security/detect-object-injection
      const application = new ApiClientApplication(apiClient.applications[appIndex]);
      if (appIndex >= 0) {
        if (application.clientId !== clientId) return Promise.reject(new Error('invalid client identifier'));
        if (application.clientSecret !== clientSecret) return Promise.reject(new Error('invalid client secret'));
        if (application.authorizationCode !== authorizationCode) return Promise.reject(new Error('invalid authorization code'));
        const nowUtc = this.now();
        if (nowUtc.getTime() > application.authorizationCodeExpirationDate.getTime()) return Promise.reject(new Error('authorization code expired'));

        const {
          accessToken,
          refreshToken,
          accessTokenExpiresIn, /*, refreshTokenExpiresIn*/
        } = await application.createTokens();
        /* eslint-disable security/detect-object-injection */
        apiClient.applications[appIndex].accessToken = accessToken;
        apiClient.applications[appIndex].refreshToken = refreshToken;
        apiClient.applications[appIndex].expiresIn = accessTokenExpiresIn;
        apiClient.applications[appIndex].authorizationCode = null;
        apiClient.applications[appIndex].authorizationCodeExpirationDate = null;
        /* eslint-enable security/detect-object-injection */
        const updateOptions = {
          applications: apiClient.applications,
          modifiedAt: this.now(),
        };
        await this.updateApiClient(apiClient, updateOptions);

        return {
          accessToken,
          refreshToken,
          expiresIn: accessTokenExpiresIn,
        };
      }

      return {
        accessToken: null,
        refreshToken: null,
        expiresIn: null,
      };
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async refreshApplicationToken(refreshApplicationAccessTokenParameters) {
    const error = RefreshApplicationAccessTokenParameters.checkForError(refreshApplicationAccessTokenParameters);
    if (error) return Promise.reject(error);

    const { refreshToken, clientId, clientSecret } = refreshApplicationAccessTokenParameters;

    try {
      const apiClient = await this.findApiClientByClientId(clientId);
      if (!apiClient) return Promise.reject(new Error('invalid client identifier'));

      // We found the client
      // Now let's proceed with the application
      /* eslint-disable security/detect-object-injection */
      const appIndex = apiClient.applications.findIndex((elem) => elem.clientId === clientId);
      const application = new ApiClientApplication(apiClient.applications[appIndex]);
      if (appIndex >= 0) {
        if (application.clientId !== clientId) return Promise.reject(new Error('invalid client identifier'));
        if (application.clientSecret !== clientSecret) return Promise.reject(new Error('invalid client secret'));
        if (application.refreshToken && application.refreshToken !== refreshToken) return Promise.reject(new Error('invalid refresh token'));

        const { accessToken, expiresIn } = await application.createAccessToken();
        apiClient.applications[appIndex].accessToken = accessToken;
        /* eslint-enable security/detect-object-injection */
        const updateOptions = {
          applications: apiClient.applications,
          modifiedAt: this.now(),
        };
        await this.updateApiClient(apiClient, updateOptions);

        return { accessToken, expiresIn };
      }

      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  // === EmailsNotSent ===
  //
  async createEmailNotSent(createEmailNotSentParameters) {
    const error = CreateEmailNotSentParameters.checkForError(createEmailNotSentParameters);
    if (error) return Promise.reject(error);

    try {
      const email = new EmailNotSent({ ...createEmailNotSentParameters });
      const id = await this.emailsNotSent.insertOneWithWriteConcern(email);
      if (id) {
        email._id = email;
        return email;
      }
      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  // === Email specific methods ===
  //
  async email(emailUserDataParameters, messageCreationMethod) {
    let message = null;
    try {
      message = messageCreationMethod(emailUserDataParameters);
      await sendMail({ message });
    } catch (error) {
      const { user, data, ip } = emailUserDataParameters;
      const { applicationName } = data;
      await this.createEmailNotSent(
        new CreateEmailNotSentParameters({
          ip,
          user,
          applicationName,
          message,
          error,
        }),
      );
    }
  }

  // === Email Static message creation methods ===
  //
  static createNewUserCreatedEmailMessage(emailUserDataParameters) {
    const error = EmailUserDataParameters.checkForError(emailUserDataParameters);
    if (error) return Promise.reject(error);

    const { user, data, ip } = emailUserDataParameters;
    const { applicationName } = data;

    return {
      from: 'team@damianos.io',
      to: 'team@damianos.io',
      subject: 'New user registration',
      text: `
  Hi admin,
  
  User ${user.firstName} (email: ${user.email}, username: ${user.userName}) has registered.

  Please take action. 
  
  ${DamianosDatabase.emailSignature(ip, applicationName)}
`,
    };
  }

  static createVerificationCodeEmailMessage(emailUserDataParameters) {
    const error = EmailUserDataParameters.checkForError(emailUserDataParameters);
    if (error) return Promise.reject(error);

    const { user, data, ip, host } = emailUserDataParameters;
    const { applicationName } = data;
    const route = `/auth/verify/${data.token}`;
    const link = `${host}${route}`;

    return {
      from: 'team@damianos.io',
      to: user.email,
      subject: 'Please confirm your account',
      text: `
  Hi ${user.firstName},

  Please confirm your email by visiting the following link (you can also copy and paste the link in the browser): 
  
  ${link}

  ${DamianosDatabase.emailSignature(ip, applicationName)}
`,
    };
  }

  static createVerificationConfirmationEmailMessage(emailUserDataParameters) {
    const error = EmailUserDataParameters.checkForError(emailUserDataParameters);
    if (error) return Promise.reject(error);

    const { user, data, ip } = emailUserDataParameters;
    const { applicationName } = data;

    return {
      from: 'team@damianos.io',
      to: user.email,
      subject: 'Thank you for the confirmation',
      text: `
  Hi ${user.firstName},

  Thank you for confirming your email! 

  ${DamianosDatabase.emailSignature(ip, applicationName)}
`,
    };
  }

  static createPasswordResetEmailMessage(emailUserDataParameters) {
    const error = EmailUserDataParameters.checkForError(emailUserDataParameters);
    if (error) return Promise.reject(error);

    const { user, data, ip, host } = emailUserDataParameters;
    const { applicationName } = data;

    const route = `/auth/auto-reset-password/${data.token}`;
    const link = `${host}${route}`;

    return {
      from: 'team@damianos.io',
      to: user.email,
      subject: 'Reset password instructions',
      text: `
  Hi ${user.firstName},

  Please visit the following link to reset your password: 
  
  ${link}

  ${DamianosDatabase.emailSignature(ip, applicationName)}
`,
    };
  }

  static createPasswordResetConfirmationEmailMessage(emailUserDataParameters) {
    const error = EmailUserDataParameters.checkForError(emailUserDataParameters);
    if (error) return Promise.reject(error);

    const { user, data, ip, host } = emailUserDataParameters;
    const { applicationName } = data;

    const route = '/auth/login';
    const link = `${host}${route}`;

    return {
      from: 'team@damianos.io',
      to: user.email,
      subject: `${applicationName} account - Password reset confirmation`,
      text: `
  Hi ${user.firstName},

  Your password has been changed.
  
  Please visit the following link to login with your new password: 
  
  ${link}

  ${DamianosDatabase.emailSignature(ip, applicationName)}
`,
    };
  }

  static createLoginAttemptEmailMessage(emailUserDataParameters) {
    const error = EmailUserDataParameters.checkForError(emailUserDataParameters);
    if (error) return Promise.reject(error);

    const { user, data, ip, host } = emailUserDataParameters;
    const { applicationName } = data;

    const route = `/auth/auto-reset-password/${data.token}`;
    const link = `${host}${route}`;

    return {
      from: 'team@damianos.io',
      to: user.email,
      subject: `Security notification regarding your ${applicationName} account`,
      text: `
  Hi ${user.firstName},

  We have detected a login with your account.
  
  If this was you: Great! You can safely ignore this email.
  
  If this wasn't you:
  If you are not the one who logged in, or this login is suspicious and you believe that someone else may have accessed your account, 
  please change your password now!
  
  ${link}

  ${DamianosDatabase.emailSignature(ip, applicationName)}
`,
    };
  }

  static emailSignature(ip, applicationName) {
    return `Detected IP address: ${ip}

  Application: ${applicationName}
  
  Your team @ ${applicationName}`;
  }
}

module.exports = DamianosDatabase;
