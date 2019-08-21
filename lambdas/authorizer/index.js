const jwt = require('jsonwebtoken');
const awsParamStore = require('aws-param-store');

// get client id and certificate for auth0 from parameter store
let AUTH0_CLIENT_ID
let AUTH0_CLIENT_PUBLIC_KEY
awsParamStore.getParameter(
    process.env.AUTH0_CLIENT_ID_PARAMETER_NAME, 
    { region: 'eu-west-1' } 
).then( (parameter) => {
    AUTH0_CLIENT_ID = parameter.Value
}).catch( (err) => {
    console.log(err);
});

awsParamStore.getParameter(
    process.env.AUTH0_CLIENT_PUBLIC_KEY_PARAMETER_NAME, 
    { region: 'eu-west-1' } 
).then( (parameter) => {
    AUTH0_CLIENT_PUBLIC_KEY = parameter.Value
}).catch( (err) => {
    console.log(err);
});

// policy helper function
const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
};

// authorizer function
module.exports.handler = (event, callback) => {
  console.log('event', event);
  if (!event.authorizationToken) {
    return callback('Unauthorized');
  }

  const tokenParts = event.authorizationToken.split(' ');
  const tokenValue = tokenParts[1];

  if (!(tokenParts[0].toLowerCase() === 'bearer' && tokenValue)) {
    // no auth token!
    return callback('Unauthorized');
  }
  const options = {
    audience: AUTH0_CLIENT_ID,
  };

  try {
    jwt.verify(tokenValue, AUTH0_CLIENT_PUBLIC_KEY, options, (verifyError, decoded) => {
      if (verifyError) {
        console.log('verifyError', verifyError);
        // 401 Unauthorized
        console.log(`Token invalid. ${verifyError}`);
        return callback('Unauthorized');
      }
      // is custom authorizer function
      console.log('valid from customAuthorizer', decoded);
      return callback(null, generatePolicy(decoded.sub, 'Allow', event.methodArn));
    });
  } catch (err) {
    console.log('catch error. Invalid token', err);
    return callback('Unauthorized');
  }
};