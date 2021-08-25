const { Validity, DateTimeUtils } = require('@1onlinesolution/dws-utils');
const ObjectId = require('mongodb').ObjectID;
const ProjectData = require('./projectData');
const ProjectStatus = require('./projectStatus');
const CreateProjectParameters = require('./requestParams/createProjectParameters');

//
// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class Project {
  constructor({
    user_id,
    application,
    label,
    _id = null, // the ObjectID
    projectData = null,
    description = '',
    status = ProjectStatus.created,
    completionEstimate = 10,
    users = [],
    createdAt = null,
    modifiedAt = null,
  } = {}) {
    this._id = _id; // the ObjectID
    this.user_id = user_id;
    this.projectData = projectData || new ProjectData();
    this.application = application;
    this.label = label;
    this.description = description;

    // ========================== status
    // 1 - Created
    // 2 - In Progress
    // 3 - Pending
    // 4 - Canceled
    // 5 - Overdue
    // 6 - Attention
    // 7 - Delivered
    this.status = status;
    this.completionEstimate = completionEstimate;
    this.users = users;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.createdAt = createdAt || nowUtc;
    this.modifiedAt = modifiedAt || nowUtc;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return Project.checkForError(this);
  }

  static checkForError(project) {
    if (!project || !(project instanceof Project)) return new Error('invalid project details');
    if (!Validity.isValidString(project.label)) return new Error('invalid project label');
    if (!Validity.isValidString(project.user_id)) return new Error('invalid user id');
    if (!project.projectData || !(project.projectData instanceof ProjectData)) return new Error('invalid project data');
    const error = ProjectData.checkForError(project.projectData);
    if (error) return error;
    return null;
  }

  static get indexMap() {
    const createIndexName = (postfix) => `index_project_${postfix}`;
    const map = new Map();
    map
      .set(createIndexName('user_id_status_completionEstimate'), {
        fieldOrSpec: { user_id: 1, status: 1, completionEstimate: 1 },
        options: {
          name: createIndexName('user_id_status_completionEstimate'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('createdAt'), {
        fieldOrSpec: { createdAt: 1 },
        options: {
          name: createIndexName('createdAt'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      });

    return map;
  }

  // ============================================================================
  // Database related
  // id => string
  static async findById(collection, id) {
    if (!id) return Promise.reject(new Error('invalid project identifier'));
    const document = await collection.findOne({ _id: ObjectId(id) });
    if (document) return new Project(document);
    return null;
  }

  static async findProjectsByUserId(collection, user_id) {
    if (!user_id) return Promise.reject(new Error('invalid user identifier'));
    return await collection.find({ user_id: ObjectId(user_id) });
  }

  static async createProject(collection, createProjectParameters) {
    // ASSUMES that user_id is from a valid user...
    const error = CreateProjectParameters.checkForError(createProjectParameters);
    if (error) return Promise.reject(error);

    try {
      const document = new Project({
        _id: createProjectParameters._id,
        user_id: createProjectParameters.user_id,
        application: createProjectParameters.application,
        label: createProjectParameters.label,
        description: createProjectParameters.description,
        status: createProjectParameters.status,
        completionEstimate: createProjectParameters.completionEstimate,
        users: createProjectParameters.users,
        createdAt: createProjectParameters.createdAt,
        modifiedAt: createProjectParameters.modifiedAt,
      });

      const _id = await collection.insertOneWithWriteConcern(document);
      if (_id) {
        document._id = _id;
        return document;
      }

      return null;
    } catch (err) {
      return Promise.reject(err);
    }
  }
}

module.exports = Project;
