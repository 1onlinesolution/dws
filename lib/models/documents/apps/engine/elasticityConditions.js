const ElasticityConditions = {
  min: 1,
  axisymmetric: 1,  // The problem satisfies the conditions for axisymmetric stress analysis.
  planeStrain: 2,   // The problem satisfies the conditions for plane strain analysis.
  planeStress: 3,   // The problem satisfies the conditions for plane stress analysis.
  max: 3,
};

module.exports = ElasticityConditions;