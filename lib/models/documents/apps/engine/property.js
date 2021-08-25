const DataTypes = require('../../dataTypes');
const PropertyTypes = require('./propertyTypes');
const MaterialTypes = require('./materialTypes');
const ElementTypes = require('./elementTypes');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');

class Property {
  constructor({
    _id = null, // the ObjectID
    label = '',
    name = '',
    description = '',
    type = PropertyTypes.undefined,
    subType = 0,
    dataType = DataTypes.undefined,
    value = null,
    siUnit = null,
    siUnitDescription = null,
    minValue = null,
    maxValue = null,
    includesMinValue = true,
    includesMaxValue = true,
  } = {}) {
    this._id = _id;
    this.label = label;
    this.name = name;
    this.description = description;
    this.type = type;
    this.subType = subType;
    this.dataType = dataType;
    this.siUnit = siUnit;
    this.siUnitDescription = siUnitDescription;
    this.minValue = minValue;
    this.maxValue = maxValue;
    this.includesMinValue = includesMinValue;
    this.includesMaxValue = includesMaxValue;

    // This property will be filled when the property is instantiated
    this.value = value;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  static get indexMap() {
    const createIndexName = (postfix) => `index_property_${postfix}`;
    const map = new Map();
    map
      .set(createIndexName('label_type_subType'), {
        fieldOrSpec: { label: 1, type: 1, subType: 1 },
        options: {
          name: createIndexName('label_type_subType'),
          unique: true,
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('name'), {
        fieldOrSpec: { name: 1 },
        options: {
          name: createIndexName('name'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      })
      .set(createIndexName('siUnit'), {
        fieldOrSpec: { siUnit: 1 },
        options: {
          name: createIndexName('siUnit'),
          background: true,
          // writeConcern: {w: 'majority', wtimeout: 100},
        },
      });

    return map;
  }

  checkForError() {
    return Property.checkForError(this);
  }

  static checkForError(property) {
    if (!property || !(property instanceof Property)) return new Error('invalid property details');
    if (!Validity.isValidString(property.label)) return new Error('invalid property label');
    if (!Validity.isValidString(property.name)) return new Error('invalid property name');
    if (!Validity.isValidString(property.description)) return new Error('invalid property description');
    if (!Validity.isValidNumber(property.type, PropertyTypes.min, PropertyTypes.max)) throw new Error('invalid property type');
    if (!Validity.isValidNumber(property.subType, Math.min(MaterialTypes.min, ElementTypes.min), Math.max(MaterialTypes.max, ElementTypes.max))) throw new Error('invalid property sub-type');
    if (!Validity.isValidNumber(property.dataType, DataTypes.min, DataTypes.max)) throw new Error('invalid data type');
    if (!Validity.isValidString(property.siUnit, 0)) throw new Error('invalid property SI units');
    if (!Validity.isValidString(property.siUnitDescription)) throw new Error('invalid material SI units description');
    return null;
  }

  static async createProperties(collection, propertiesArray) {
    if (!propertiesArray || propertiesArray.constructor !== Array) return Promise.reject(new Error('invalid material properties array'));
    propertiesArray.forEach((item) => {
      if (!item || !(item instanceof Property)) return new Error('invalid material properties array');
    });

    propertiesArray.forEach((item) => {
      const error = Property.checkForError(item);
      if (error) return Promise.reject(error);
    });

    try {
      const _ids = await collection.insertManyWithWriteConcern(propertiesArray);
      return _ids && _ids instanceof Array && _ids.length === propertiesArray.length;
    } catch (err) {
      return Promise.reject(err);
    }
  }
}

module.exports = Property;
