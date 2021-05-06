const ObjectId = require('mongodb').ObjectID;
const Project = require('../../models/documents/apps/project');
const Property = require('../../models/documents/apps/engine/property');
const ProjectStatus = require('../../models/documents/apps/projectStatus');
const MongoDatabase = require('../mongodb/mongoDatabase');
const MongoConnection = require('../mongodb/mongoConnection');
const MongoCollection = require('../mongodb/mongoCollection');
const defaultDatabaseProperties = require('../../models/documents/apps/engine/defaultDatabaseProperties');

const COLLECTION_NAME_PROJECTS = 'projects';
const COLLECTION_NAME_PROPERTIES = 'properties';

class StructureDatabase extends MongoDatabase {
  constructor({ connection, databaseName, logger }) {
    super(connection, databaseName);

    this._properties = new MongoCollection(this, COLLECTION_NAME_PROPERTIES);
    this._projects = new MongoCollection(this, COLLECTION_NAME_PROJECTS);
    this._logger = logger;

    return this;
  }

  // Accessor Properties
  get properties() {
    return this._properties;
  }

  get projects() {
    return this._projects;
  }

  get logger() {
    return this._logger;
  }

  async createIndex() {
    await this._properties.createIndexes(Property.indexMap);
    await this._projects.createIndexes(Project.indexMap);
  }

  static async createDatabase({
    name,
    logger,
    connectionString,
    connectionOptions = {
      useUnifiedTopology: true,
    },
  } = {}) {
    try {
      const connection = new MongoConnection(connectionString, connectionOptions);
      await connection.connect();
      const database = new StructureDatabase({ connection, name, logger });
      await database.createIndex();
      return database;
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async getStatistics(user_id) {
    return {
      projectCount: await this.projects.count({ user_id: user_id }),
      projectActiveCount: await this.projects.count({ user_id: user_id, status: { $lt: ProjectStatus.delivered } }),
      projectDeliveredCount: await this.projects.count({ user_id: user_id, status: { $eq: ProjectStatus.delivered } }),
      projectAttentionCount: await this.projects.count({
        user_id: user_id,
        status: { $in: [ProjectStatus.overdue, ProjectStatus.attention] },
      }),
    };
  }

  async findProject(filter = {}) {
    try {
      return await this.projects.find(filter);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  // user_id => string
  async findProjectByUserId(user_id) {
    if (!user_id) return Promise.reject(new Error('invalid user id'));
    return await this.projects.find({ user_id: user_id });
  }

  async findProjectById(projectId) {
    if (!projectId) return Promise.reject(new Error('invalid project id'));
    return await this.projects.findOne({ _id: ObjectId(projectId) });
  }

  // ===================================================================
  // creation/modification operations

  async createProject(createProjectParameters) {
    return await Project.createProject(this.projects, createProjectParameters);
  }

  async createDefaultProperties() {
    if (await this.properties.findOne({ label: 'rho' })) return;
    await Property.createProperties(this.properties, defaultDatabaseProperties);
  }
}

module.exports = StructureDatabase;
