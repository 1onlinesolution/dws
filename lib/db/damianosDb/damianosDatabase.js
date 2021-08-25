const { Validity, Converter, DateTimeUtils } = require('@1onlinesolution/dws-utils');
const MongoDatabase = require('@1onlinesolution/dws-mongodb/lib/mongoDatabase');
const MongoCollection = require('@1onlinesolution/dws-mongodb/lib/mongoCollection');
const { ObjectId } = require('@1onlinesolution/dws-mongodb');
const { PasswordService, EncryptionService, JwtService } = require('@1onlinesolution/dws-crypto');
const { EmailService } = require('@1onlinesolution/dws-mail');
const User = require('../../models/documents/sso/user');
const Address = require('../../models/documents/sso/address');
const UserLogin = require('../../models/documents/sso/userLogin');
const UserRole = require('../../models/documents/sso/userRole');
const Product = require('../../models/documents/orderPipeline/product');
const EmailNotSent = require('../../models/documents/sso/emailNotSent');
const ApiClientApplication = require('../../models/documents/sso/apiClientApplication');
const CreateUserParameters = require('../../models/documents/sso/requestParams/createUserParameters');
const CreateUserAddressParameters = require('../../models/documents/sso/requestParams/createUserAddressParameters');
const DeleteUserAddressParameters = require('../../models/documents/sso/requestParams/deleteUserAddressParameters');
const UpdateUserAddressParameters = require('../../models/documents/sso/requestParams/updateUserAddressParameters');
const UpdateUserParameters = require('../../models/documents/sso/requestParams/updateUserParameters');
const DeleteUserParameters = require('../../models/documents/sso/requestParams/deleteUserParameters');
const LoginUserParameters = require('../../models/documents/sso/requestParams/loginUserParameters');
const CreateApiClientApplicationParameters = require('../../models/documents/sso/requestParams/createApiClientApplicationParameters');
const UpdateApiClientApplicationParameters = require('../../models/documents/sso/requestParams/updateApiClientApplicationParameters');
const AuthorizeApiClientApplicationParameters = require('../../models/documents/sso/requestParams/authorizeApiClientApplicationParameters');
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
const CreateUserLoginParameters = require('../../models/documents/sso/requestParams/createUserLoginParameters');

const TOKEN_LENGTH = 16;

const COLLECTION_NAME_USERS = 'user';
const COLLECTION_NAME_ADDRESS = 'address';
const COLLECTION_NAME_USER_LOGINS = 'user_login';
const COLLECTION_NAME_PRODUCTS = 'product';
const COLLECTION_NAME_COUNTRIES = 'country';
const COLLECTION_NAME_US_STATES = 'us_state';
const COLLECTION_NAME_API_CLIENT_APP = 'api_client_application';
const COLLECTION_NAME_EMAIL_NOT_SENT = 'emails_not_sent';

class DamianosDatabase extends MongoDatabase {
  constructor({
    connectionString,
    name,
    logger,
    applicationName,
    encryptionKey = process.env.ENCRYPTION_KEY,
    jwt_algorithm = process.env.JWT_ALGORITHM,
    jwt_accessTokenSecretKey = process.env.JWT_ACCESS_TOKEN_SECRET_KEY,
    jwt_refreshTokenSecretKey = process.env.JWT_REFRESH_TOKEN_SECRET_KEY,
    jwt_accessTokenExpiresIn = process.env.JWT_EXPIRATION_ACCESS_TOKEN,
    jwt_refreshTokenExpiresIn = process.env.JWT_EXPIRATION_REFRESH_TOKEN,
  }) {
    super(connectionString, name);
    if (!Validity.isValidString(applicationName, 2)) throw new Error('invalid application name');
    if (!logger) throw new Error('invalid logger');
    if (!encryptionKey) throw new Error('invalid encryption key');
    if (!jwt_algorithm) throw new Error('invalid JWT algorithm');
    if (!jwt_accessTokenSecretKey) throw new Error('invalid JWT access token secret key');
    if (!jwt_refreshTokenSecretKey) throw new Error('invalid JWT refresh token secret key');
    if (!jwt_accessTokenExpiresIn) throw new Error('invalid JWT access token expiration period');
    if (!jwt_refreshTokenExpiresIn) throw new Error('invalid JWT refresh token expiration period');

    this.applicationName = applicationName;

    this._users = new MongoCollection(this, COLLECTION_NAME_USERS);
    this._addresses = new MongoCollection(this, COLLECTION_NAME_ADDRESS);
    this._userLogins = new MongoCollection(this, COLLECTION_NAME_USER_LOGINS);
    this._products = new MongoCollection(this, COLLECTION_NAME_PRODUCTS);
    this._countries = new MongoCollection(this, COLLECTION_NAME_COUNTRIES);
    this._statesUS = new MongoCollection(this, COLLECTION_NAME_US_STATES);
    this._apiClientApplications = new MongoCollection(this, COLLECTION_NAME_API_CLIENT_APP);
    this._emailsNotSent = new MongoCollection(this, COLLECTION_NAME_EMAIL_NOT_SENT);
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

  get addresses() {
    return this._addresses;
  }

  get userLogins() {
    return this._userLogins;
  }

  get products() {
    return this._products;
  }

  get countries() {
    return this._countries;
  }

  get statesUS() {
    return this._statesUS;
  }

  get apiClientApplications() {
    return this._apiClientApplications;
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
    applicationName,
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
      const database = new DamianosDatabase({
        connectionString,
        name,
        logger,
        applicationName,
        encryptionKey,
        jwt_algorithm,
        jwt_accessTokenSecretKey,
        jwt_refreshTokenSecretKey,
        jwt_accessTokenExpiresIn,
        jwt_refreshTokenExpiresIn,
      });
      await database.connect();
      await database.createIndex();
      await database.populateWorldCollections();
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
    await this._addresses.createIndexes(Address.indexMap);
    await this._userLogins.createIndexes(UserLogin.indexMap);
    await this._products.createIndexes(Product.indexMap);
    await this._apiClientApplications.createIndexes(ApiClientApplication.indexMap);
    await this._emailsNotSent.createIndexes(EmailNotSent.indexMap);
  }

  async populateWorldCollections() {
    const countriesCount = await this.countries.count();
    if (countriesCount === 0) {
      const countries = require('./countries.json');
      await this.countries.insertManyWithWriteConcern(countries);
    }

    const statesCount = await this.statesUS.count();
    if (statesCount === 0) {
      const states = require('./statesUS.json');
      await this.statesUS.insertManyWithWriteConcern(states);
    }
  }

  async statistics() {
    return await this.database.command({ dbStats: 1 });
  }

  // === Error handling ===
  //

  static isMongoError(error) {
    return error.name === 'MongoError';
  }

  errorMessage(error) {
    if (DamianosDatabase.isMongoError(error)) {
      switch (error.code) {
        case 11000:
          return 'attempt to insert a duplicate record in the database';

        default:
          return 'database error detected';
      }
    }

    return error.message;
  }

  // === User ===
  //

  isUserVerified(user) {
    return user.verified;
  }

  hasVerificationToken(user) {
    return user.verification_token;
  }

  static async generateToken(length = TOKEN_LENGTH) {
    return await PasswordService.randomBytesAsToken(length);
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

  async findUserByApiClientId(api_client_id) {
    if (!api_client_id) return Promise.reject(new Error('invalid API Client identifier'));
    try {
      const document = await this.users.findOne({ api_client_id: ObjectId(api_client_id) });
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

  // async findUserApplications() {
  //   // TODO: To be reviewed!!!
  //   // https://docs.mongodb.com/manual/reference/method/db.collection.aggregate/
  //   // https://docs.mongodb.com/manual/reference/operator/aggregation/lookup/#use-lookup-with-mergeobjects
  //   // https://docs.mongodb.com/manual/tutorial/aggregation-zip-code-data-set/
  //   // https://stackoverflow.com/a/48631398
  //   // https://www.djamware.com/post/5d7f3ab0290dd8b012d95a9d/mongodb-tutorial-aggregate-method-example
  //   // https://dzone.com/articles/three-approaches-to-creating-a-sql-join-equivalent
  //   try {
  //     const apps = await this.users.aggregate([
  //       {
  //         $lookup: {
  //           from: this.apiClients.collectionName,
  //           localField: 'applications',
  //           foreignField: 'applications.clientId',
  //           as: 'app_info',
  //         },
  //       },
  //       {
  //         $replaceRoot: { newRoot: { $mergeObjects: [{ $arrayElemAt: ['$fromItems', 0] }, '$$ROOT'] } },
  //       },
  //       { $project: { fromItems: 0 } },
  //     ]);
  //
  //     // add an array of application names to hold the data
  //     const application_names = [];
  //     await apps.forEach(
  //       (doc) => {
  //         doc.app_info.forEach((item) => {
  //           item.applications.forEach((app) => {
  //             // found an application, let's get the name
  //             application_names.push(app.applicationName);
  //           });
  //         });
  //       } /*, err => {
  //         if (err) ...
  //       }*/,
  //     );
  //
  //     // return the app names
  //     return application_names;
  //   } catch (err) {
  //     return Promise.reject(err);
  //   }
  // }

  async createUser(createUserParameters) {
    const error = CreateUserParameters.checkForError(createUserParameters);
    if (error) return Promise.reject(error);

    try {
      let user = await this.findUserByEmail(createUserParameters.email);
      if (user) return Promise.reject(new Error('email already exists'));

      const hash = await PasswordService.hashPassword(createUserParameters.password);
      user = new User({
        firstName: createUserParameters.firstName,
        lastName: createUserParameters.lastName,
        userName: createUserParameters.userName,
        email: createUserParameters.email,
        autoVerify: createUserParameters.autoVerify,
        newsletter: createUserParameters.newsletter,
        password: hash,
        verification_token: await DamianosDatabase.generateToken(),
      });

      const userId = await this.users.insertOneWithWriteConcern(user);
      if (userId) {
        user._id = userId;
        delete user.password;

        if (user.autoVerify) {
          // Email user the reset-password link
          await this.emailUserVerificationInfo(user, createUserParameters.emailParameters);
        } else {
          await this.emailAdminNewUserRegistered(user, createUserParameters.emailParameters);
        }

        return user;
      }

      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async emailAdminNewUserRegistered(user, emailParameters) {
    if (!user) return Promise.reject(new Error('invalid user information'));
    if (user.verified) return Promise.reject(new Error('user is already verified'));
    const error = EmailParameters.checkForError(emailParameters);
    if (error) return Promise.reject(error);

    try {
      // Email user the reset-password link
      const emailUserDataParameters = new EmailUserDataParameters({
        user: User.getPayloadForSession(user),
        data: {
          applicationName: this.applicationName,
        },
        ...emailParameters,
      });

      await this.email(emailUserDataParameters, DamianosDatabase.createNewUserCreatedEmailMessage);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async emailUserVerificationInfo(user, emailParameters) {
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
            verification_token: user.verification_token,
          }),
          applicationName: this.applicationName,
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
            applicationName: this.applicationName,
          },
          ...loginUserParameters,
        });
        await this.email(emailUserDataParameters, DamianosDatabase.createLoginAttemptEmailMessage);
      }

      const loginIsAllowed = user && user.verified;
      if (loginIsAllowed) {
        if (!(await this.createUserLoginRecord(new CreateUserLoginParameters({ ...loginUserParameters })))) return null;
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

      const { accessToken, refreshToken } = await DamianosDatabase.createVerifiedUserTokens(user);
      user.jwt_access_token = accessToken;
      user.jwt_refresh_token = refreshToken;

      // Update the database
      const nowUtc = this.now();
      await this.updateUserCore(User.id(user), {
        jwt_access_token: user.jwt_access_token,
        jwt_refresh_token: user.jwt_refresh_token,
        'stats.lastLoggedInAt': nowUtc,
        'stats.countLogIns': 1 + user.stats.countLogIns,
        createdRefreshTokenAt: nowUtc,
        modifiedAt: nowUtc,
      });
      delete user.password;
      return { user, old_jwt_refresh_token };
    } catch (err) {
      return Promise.reject(err);
    }
  }

  static async createVerifiedUserTokens(user) {
    return await user.createVerifiedUserTokens();
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

  async deleteUser(deleteUserParameters) {
    const error = DeleteUserParameters.checkForError(deleteUserParameters);
    if (error) return Promise.reject(error);
    const { user_id } = deleteUserParameters;

    try {
      const user = await this.findUserById(user_id);
      if (!user) return Promise.reject(new Error('invalid user'));
      if (!user.verified) return Promise.reject(new Error('user is not verified'));

      // TODO: delete user AND ALL its data !!!
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

  async createUserLoginRecord(createUserLoginParameters) {
    try {
      const userLogin = new UserLogin({ ...createUserLoginParameters });
      const userLoginId = await this.userLogins.insertOneWithWriteConcern(userLogin);
      if (userLoginId) {
        userLogin._id = userLoginId;
      }
      return userLoginId ? userLogin : null;
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
      const { user, ip, host } = emailUserParameters;
      const verification_token = await DamianosDatabase.generateToken();
      const updated = await this.updateUserCore(User.id(user), {
        verified: false,
        verification_token: verification_token,
        modifiedAt: this.now(),
      });

      if (updated) {
        const afterTwoHoursUtc = this.now();
        const encryptionService = new EncryptionService({ encryptionKey: this.encryptionKey });
        afterTwoHoursUtc.setTime(afterTwoHoursUtc.getTime() + 2 * 60 * 60 * 1000);
        const emailUserDataParameters = new EmailUserDataParameters({
          data: {
            token: await encryptionService.encryptObjectCompact({
              email: emailUserParameters.user.email,
              expirationDate: afterTwoHoursUtc,
              verification_token: verification_token,
            }),
            applicationName: this.applicationName,
          },
          user: User.getPayloadForSession(user),
          ip,
          host,
        });

        await this.email(emailUserDataParameters, DamianosDatabase.createVerificationCodeEmailMessage);
        return true;
      }
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
      const { email, expirationDate, verification_token } = data;
      const nowUtc = this.now();
      if (nowUtc > expirationDate) return Promise.reject(new Error('token has expired'));

      const user = await this.findUserByEmail(email);
      if (!user || !user.requiresVerification) return Promise.reject(new Error('invalid user'));
      if (user.verification_token !== verification_token) return Promise.reject(new Error('invalid user verification token'));

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

        // Email user confirmation
        const emailUserDataParameters = new EmailUserDataParameters({
          user: User.getPayloadForSession(user),
          data: {
            applicationName: this.applicationName,
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
          applicationName: this.applicationName,
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
        // Email user the reset-password link
        const emailUserDataParameters = new EmailUserDataParameters({
          user: User.getPayloadForSession(user),
          data: {
            applicationName: this.applicationName,
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
        // Email user the reset-password link
        const emailUserDataParameters = new EmailUserDataParameters({
          user: User.getPayloadForSession(user),
          data: {
            applicationName: this.applicationName,
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

  // === Addresses ===
  //
  async findUserAddress(address_id) {
    if (!address_id) return Promise.reject(new Error('invalid address identifier'));
    return await this.addresses.findOne({ _id: ObjectId(address_id) });
  }

  async findUserAddresses(user_id) {
    if (!user_id) return Promise.reject(new Error('invalid user identifier'));
    return await this.findUserAddressesCore({ user_id: user_id });
  }

  async findCountryAddresses(country) {
    if (!country) return Promise.reject(new Error('invalid country'));
    return await this.findUserAddressesCore({ country: ObjectId(country) });
  }

  async findUserAddressesCore(filter) {
    if (!filter) return Promise.reject(new Error('invalid filter'));
    try {
      const sort = { isDefault: -1 };
      const documents = await this.addresses.findAndSort(filter, {}, sort);
      if (documents && documents.length > 0) {
        const addresses = [];
        documents.forEach(item => {
          const address = new Address({ ...item });
          addresses.push(address);
        });
        return addresses;
      }
      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async createUserAddress(createUserAddressParameters) {
    const error = CreateUserAddressParameters.checkForError(createUserAddressParameters);
    if (error) return Promise.reject(error);
    const { user_id } = createUserAddressParameters;

    try {
      const addresses = await this.findUserAddresses(user_id);
      if (!addresses || addresses.length === 0) {
        // If this is the first address, this will be the default address
        createUserAddressParameters.address.isDefault = true;
        createUserAddressParameters.address.isBilling = true;
        createUserAddressParameters.address.isShipping = true;
      } else {
        let addressWithDefaultId = null;
        let addressWithBillingId = null;
        let addressWithShippingId = null;
        if (addresses) {
          if (createUserAddressParameters.address.isDefault) {
            addresses.forEach(address => {
              if (address.isDefault) {
                address.isDefault = false;
                if (!addressWithDefaultId) {
                  addressWithDefaultId = address._id;
                }
              }
            });
          }
          if (createUserAddressParameters.address.isBilling) {
            addresses.forEach(address => {
              if (address.isBilling) {
                address.isBilling = false;
                if (!addressWithBillingId) {
                  addressWithBillingId = address._id;
                }
              }
            });
          }
          if (createUserAddressParameters.address.isShipping) {
            addresses.forEach(address => {
              if (address.isShipping) {
                address.isShipping = false;
                if (!addressWithShippingId) {
                  addressWithShippingId = address._id;
                }
              }
            });
          }
        }

        if (addressWithDefaultId) {
          await this.updateAddressCore(addressWithDefaultId, { isDefault: false, modifiedAt: this.now() });
        }

        if (addressWithBillingId) {
          await this.updateAddressCore(addressWithBillingId, { isBilling: false, modifiedAt: this.now() });
        }

        if (addressWithShippingId) {
          await this.updateAddressCore(addressWithShippingId, { isShipping: false, modifiedAt: this.now() });
        }
      }

      const address = new Address({ ...createUserAddressParameters.address });
      address._id = await this.addresses.insertOneWithWriteConcern(address);
      return address;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async updateUserAddress(updateUserAddressParameters) {
    const error = UpdateUserAddressParameters.checkForError(updateUserAddressParameters);
    if (error) return Promise.reject(error);
    const { user_id, address_id } = updateUserAddressParameters;

    try {
      const addresses = await this.findUserAddresses(user_id);
      const address = await this.findUserAddress(address_id);
      if (!address) return Promise.reject(new Error('invalid address identifier'));

      let addressWithDefaultId = null;
      let addressWithBillingId = null;
      let addressWithShippingId = null;
      if (addresses && addresses.length > 0) {
        if (updateUserAddressParameters.address.isDefault) {
          addresses.forEach(address => {
            if (address.isDefault) {
              address.isDefault = false;
              if (!addressWithDefaultId) {
                addressWithDefaultId = address._id;
              }
            }
          });
        }
        if (updateUserAddressParameters.address.isBilling) {
          addresses.forEach(address => {
            if (address.isBilling) {
              address.isBilling = false;
              if (!addressWithBillingId) {
                addressWithBillingId = address._id;
              }
            }
          });
        }
        if (updateUserAddressParameters.address.isShipping) {
          addresses.forEach(address => {
            if (address.isShipping) {
              address.isShipping = false;
              if (!addressWithShippingId) {
                addressWithShippingId = address._id;
              }
            }
          });
        }
      }

      if (addressWithDefaultId) {
        await this.updateAddressCore(addressWithDefaultId, { isDefault: false, modifiedAt: this.now() });
      }

      if (addressWithBillingId) {
        await this.updateAddressCore(addressWithBillingId, { isBilling: false, modifiedAt: this.now() });
      }

      if (addressWithShippingId) {
        await this.updateAddressCore(addressWithShippingId, { isShipping: false, modifiedAt: this.now() });
      }

      delete updateUserAddressParameters.user_id;
      delete updateUserAddressParameters.address_id;
      delete updateUserAddressParameters.address._id;
      return await this.updateAddressCore(address_id, {
        ...updateUserAddressParameters.address,
        modifiedAt: this.now(),
      });
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async deleteUserAddress(deleteUserAddressParameters) {
    const error = DeleteUserAddressParameters.checkForError(deleteUserAddressParameters);
    if (error) return Promise.reject(error);
    const { user_id, address_id } = deleteUserAddressParameters;

    try {
      const addresses = await this.findUserAddresses(user_id);
      if (addresses && addresses.length > 0) {
        addresses.forEach(address => {
          if (address._id.toString() === address_id && address.isDefault) {
            // Do not delete the default address
            return false;
          }
        });

        let hasDefaultId = deleteUserAddressParameters.isDefault;
        let hasBillingId = deleteUserAddressParameters.isBilling;
        let hasShippingId = deleteUserAddressParameters.isShipping;
        if (hasDefaultId) {
          await this.updateAddressCore(addresses[0]._id, { isDefault: true, modifiedAt: this.now() });
        }
        if (hasBillingId) {
          await this.updateAddressCore(addresses[0]._id, { isBilling: true, modifiedAt: this.now() });
        }
        if (hasShippingId) {
          await this.updateAddressCore(addresses[0]._id, { isShipping: true, modifiedAt: this.now() });
        }
      }
      return await this.addresses.deleteOneWithWriteConcern({ _id: ObjectId(address_id) });
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async updateAddressCore(address_id, updateOptions) {
    if (!address_id) return Promise.reject(new Error('invalid address identifier'));
    if (!updateOptions) return Promise.reject(new Error('invalid address update options'));
    return await this.addresses.updateOneWithWriteConcern({ _id: ObjectId(address_id) }, { $set: updateOptions });
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
    return await this.products.deleteOneWithWriteConcern({ _id: ObjectId(productId) });
  }

  // === Countries ===
  //
  async findCountries(filter = {}) {
    try {
      return await this.countries.find(filter);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  // === US States ===
  //
  async findStatesUS(filter = {}) {
    try {
      return await this.statesUS.find(filter);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  // === ApiClient Application ===
  //

  async findApplicationByAppClientId(api_client_id) {
    if (!api_client_id) return Promise.reject(new Error('invalid API client identifier'));
    return await this.apiClientApplications.find({ apiClientId: ObjectId(api_client_id) });
  }

  async findApiClientApplicationById(apiClientApplicationId) {
    if (!apiClientApplicationId) return Promise.reject(new Error('invalid api client application identifier'));

    try {
      const document = await this.apiClientApplications.findOne({ _id: ObjectId(apiClientApplicationId) });
      if (document) return new ApiClientApplication(document);
      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async findApiClientApplication(apiClientId, applicationName, websiteUrl) {
    if (!apiClientId) return Promise.reject(new Error('invalid API client identifier'));
    if (!applicationName) return Promise.reject(new Error('invalid API client application name'));
    if (!websiteUrl) return Promise.reject(new Error('invalid API client application website URL'));

    try {
      const document = await this.apiClientApplications.findOne({ apiClientId, applicationName, websiteUrl });
      if (document) return new ApiClientApplication(document);
      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async findApiClientApplicationByAuthorizationCode(authorizationCode) {
    if (!authorizationCode) return Promise.reject(new Error('invalid API client application authorization code'));

    try {
      const document = await this.apiClientApplications.findOne({ authorizationCode });
      if (document) return new ApiClientApplication(document);
      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async findApiClientApplicationByRefreshToken(refreshToken) {
    if (!refreshToken) return Promise.reject(new Error('invalid API client application refresh token'));

    try {
      const document = await this.apiClientApplications.findOne({ refreshToken });
      if (document) return new ApiClientApplication(document);
      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async updateApiClientApplicationCore(apiClientApplication, updateOptions) {
    if (!apiClientApplication || !apiClientApplication._id) return Promise.reject(new Error('invalid api client application information'));
    if (!updateOptions) return Promise.reject(new Error('invalid update options'));

    // Update the database
    return await this.apiClientApplications.updateOneWithWriteConcern(
      { _id: ObjectId(apiClientApplication._id) },
      { $set: updateOptions },
    );
  }

  async registerApiClientApplication(createApiClientApplicationParameters) {
    const error = CreateApiClientApplicationParameters.checkForError(createApiClientApplicationParameters);
    if (error) return Promise.reject(error);

    try {
      const { apiClientId, applicationName, websiteUrl } = createApiClientApplicationParameters;
      const apiClientApp = await this.findApiClientApplication(apiClientId, applicationName, websiteUrl);
      if (apiClientApp) return Promise.reject(new Error('API client application already exists'));

      const app = new ApiClientApplication({ ...createApiClientApplicationParameters });
      app._id = await this.apiClientApplications.insertOneWithWriteConcern(app);

      return app;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async updateApiClientApplication(updateApiClientApplicationParameters) {
    const error = UpdateApiClientApplicationParameters.checkForError(updateApiClientApplicationParameters);
    if (error) return Promise.reject(error);

    const {
      apiClientApplicationId,
      applicationName,
      applicationDescription,
      websiteUrl,
      returnUrl,
    } = updateApiClientApplicationParameters;
    try {
      let apiClientApplication = await this.findApiClientApplicationById(apiClientApplicationId);
      if (!apiClientApplication) return Promise.reject(new Error('api client application not found'));

      const nowUtc = this.now();
      const updateOptions = {
        applicationName,
        applicationDescription,
        websiteUrl,
        returnUrl,
        modifiedAt: nowUtc,
      };

      // Update the database
      return await this.updateProductCore(apiClientApplication, updateOptions);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async generateApplicationAuthorizationCode(createApiClientApplicationAuthorizationCodeParameters) {
    const error = CreateApiClientApplicationAuthorizationCodeParameters.checkForError(createApiClientApplicationAuthorizationCodeParameters);
    if (error) return Promise.reject(error);
    const { apiClientApplicationId /*, redirectUrl*/ } = createApiClientApplicationAuthorizationCodeParameters;

    try {
      const apiClientApp = await this.findApiClientApplicationById(apiClientApplicationId);
      if (!apiClientApp) return Promise.reject(new Error('API client application not found'));

      // We found the client application
      const modifiedApiClientApp = await ApiClientApplication.generateAuthorizationCode(apiClientApp);
      const updateOptions = {
        authorizationCode: modifiedApiClientApp.authorizationCode,
        authorizationCodeExpirationDate: modifiedApiClientApp.authorizationCodeExpirationDate,
        modifiedAt: this.now(),
      };

      if (await this.updateApiClientApplicationCore(apiClientApp, updateOptions)) {
        return modifiedApiClientApp.authorizationCode;
      }

      return await this.updateApiClientApplicationCore(apiClientApp, updateOptions)
        ? modifiedApiClientApp.authorizationCode
        : null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async authorizeApplication(authorizeApiClientApplicationParameters) {
    const error = AuthorizeApiClientApplicationParameters.checkForError(authorizeApiClientApplicationParameters);
    if (error) return Promise.reject(error);
    const { authorizationCode, clientId, clientSecret } = authorizeApiClientApplicationParameters;

    try {
      const apiClientApp = await this.findApiClientApplicationByAuthorizationCode(authorizationCode);
      if (!apiClientApp) return Promise.reject(new Error('API client application not found'));

      // We found the client application
      const result = await apiClientApp.createTokens();
      const { accessToken, refreshToken, accessTokenExpiresIn, refreshTokenExpiresIn } = result;
      const updateOptions = {
        accessToken,
        refreshToken,
        accessTokenExpiresIn,
        refreshTokenExpiresIn,
        modifiedAt: this.now(),
      };

      return await this.updateApiClientApplicationCore(apiClientApp, updateOptions)
        ? {
          accessToken,
          refreshToken,
          accessTokenExpiresIn,
          refreshTokenExpiresIn,
        }
        : null;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async refreshApplicationToken(refreshApplicationAccessTokenParameters) {
    const error = RefreshApplicationAccessTokenParameters.checkForError(refreshApplicationAccessTokenParameters);
    if (error) return Promise.reject(error);

    const { refreshToken, clientId, clientSecret } = refreshApplicationAccessTokenParameters;

    try {
      const user = await this.findUserByApiClientId(clientId);
      if (!user) return Promise.reject(new Error('API client identifier not found'));

      const apiClientApp = await this.findApiClientApplicationByRefreshToken(refreshToken);
      if (!apiClientApp) return Promise.reject(new Error('API client application not found'));
      if (apiClientApp.apiClientId !== clientId) return Promise.reject(new Error('invalid API client identifier'));
      if (user.api_client_secret !== clientSecret) return Promise.reject(new Error('invalid API client secret'));

      // We found the client application
      const result = await apiClientApp.createAccessToken();
      const { accessToken, accessTokenExpiresIn } = result;
      const updateOptions = {
        accessToken: accessToken,
        accessTokenExpiresIn: accessTokenExpiresIn,
        modifiedAt: this.now(),
      };

      return await this.updateApiClientApplicationCore(apiClientApp, updateOptions)
        ? {
          accessToken,
          accessTokenExpiresIn,
        }
        : null;
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
      await EmailService.sendMail({ message });
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
