const PropertyTypes = require('./propertyTypes');
const MaterialTypes = require('./materialTypes');
const ElementTypes = require('./elementTypes');
const Property = require('./property');
const defaultDatabaseProperties = require('./defaultDatabaseProperties');
const Validity = require('@1onlinesolution/dws-utils/lib/validity');

// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class ElementGroup {
  constructor({ label, description = '', propertyValues = undefined } = {}) {
    this.label = label;
    this.description = description || '';
    this.propertyValues = propertyValues || [];

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  get elementType() {
    if (this.propertyValues) {
      for (let i = 0; i < this.propertyValues.length; ++i) {
        // Found in properties; return the type
        // eslint-disable-next-line security/detect-object-injection
        if (this.propertyValues[i].type === PropertyTypes.elementGroup) return this.propertyValues[i].subType;
      }
    }

    // Not found in properties; perhaps it has no properties yet
    return ElementTypes.undefined;
  }

  checkForError() {
    return ElementGroup.checkForError(this);
  }

  static checkForError(elementGroup) {
    if (!elementGroup || !(elementGroup instanceof ElementGroup)) return new Error('invalid element group details');
    if (!Validity.isValidString(elementGroup.label)) return new Error('invalid element group label');
    if (!elementGroup.propertyValues) return new Error('invalid element group properties');
    elementGroup.propertyValues.forEach((item) => {
      if (!(item instanceof Property)) return new Error('invalid element group properties');
    });
    return null;
  }

  static createElasticTorsionGroup(label, description = '') {
    return ElementGroup.createElementGroup(label, description, MaterialTypes.elasticIsotropic, ElementTypes.torsion);
  }

  static createElasticTrussGroup(label, description = '') {
    return ElementGroup.createElementGroup(label, description, MaterialTypes.elasticIsotropic, ElementTypes.truss);
  }

  static createElasticSolid2dGroup(label, description = '') {
    return ElementGroup.createElementGroup(label, description, MaterialTypes.elasticIsotropic, ElementTypes.solid2d);
  }

  static createElasticSolid3dGroup(label, description = '') {
    return ElementGroup.createElementGroup(label, description, MaterialTypes.elasticIsotropic, ElementTypes.solid3d);
  }

  static createElementGroup(label, description = '', materialType = MaterialTypes.elasticIsotropic, elementType = ElementTypes.truss) {
    if (!label) throw new Error('invalid element group label');

    const materialProperties = [];
    const elementProperties = [];
    defaultDatabaseProperties.forEach((item) => {
      if (item.type === PropertyTypes.material && item.subType === materialType) {
        materialProperties.push(item);
      } else if (item.type === PropertyTypes.elementGroup && item.subType === elementType) {
        elementProperties.push(item);
      }
    });

    if (materialProperties.length === 0 || elementProperties.length === 0) throw new Error('invalid element group properties');

    return new ElementGroup({
      label,
      description,
      propertyValues: [...materialProperties, ...elementProperties],
    });
  }
}

module.exports = ElementGroup;
