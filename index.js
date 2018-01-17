const passport = require("passport-strategy");
const util = require("util");
const saml = require("passport-saml").SAML;

function SpidStrategy(options, verify) {
  if (typeof options === "function") {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error("SAML authentication strategy requires a verify function");
  }

  this.name = "spid";

  passport.Strategy.call(this);

  this.spidOptions = options;
  this._verify = verify;
  this._passReqToCallback = !!options.passReqToCallback;
  this._authnRequestBinding = options.authnRequestBinding || "HTTP-Redirect";
}

util.inherits(SpidStrategy, passport.Strategy);

SpidStrategy.prototype.authenticate = function(req, options) {
  const self = this;

  const spidOptions = this.spidOptions.sp;

  const entityID = req.query.entityID;
  if (entityID !== undefined) {
    const idp = this.spidOptions.idp[entityID];
    spidOptions.entryPoint = idp.entryPoint;
    spidOptions.cert = idp.cert;
  }

  const samlClient = new saml(spidOptions);

  options.samlFallback = options.samlFallback || "login-request";

  function validateCallback(err, profile, loggedOut) {
    if (err) {
      return self.error(err);
    }

    if (loggedOut) {
      req.logout();
      if (profile) {
        req.samlLogoutRequest = profile;
        return samlClient.getLogoutResponseUrl(req, redirectIfSuccess);
      }
      return self.pass();
    }

    const verified = function(err, user, info) {
      if (err) {
        return self.error(err);
      }

      if (!user) {
        return self.fail(info);
      }

      self.success(user, info);
    };

    if (self._passReqToCallback) {
      self._verify(req, profile, verified);
    } else {
      self._verify(profile, verified);
    }
  }

  function redirectIfSuccess(err, url) {
    if (err) {
      self.error(err);
    } else {
      self.redirect(url);
    }
  }

  if (req.body && req.body.SAMLResponse) {
    samlClient.validatePostResponse(req.body, validateCallback);
  } else if (req.body && req.body.SAMLRequest) {
    samlClient.validatePostRequest(req.body, validateCallback);
  } else {
    const requestHandler = {
      "login-request": function() {
        if (self._authnRequestBinding === "HTTP-POST") {
          samlClient.getAuthorizeForm(req, function(err, data) {
            if (err) {
              self.error(err);
            } else {
              const res = req.res;
              res.send(data);
            }
          });
        } else {
          // Defaults to HTTP-Redirect
          samlClient.getAuthorizeUrl(req, redirectIfSuccess);
        }
      }.bind(self),
      "logout-request": function() {
        samlClient.getLogoutUrl(req, redirectIfSuccess);
      }.bind(self)
    }[options.samlFallback];

    if (typeof requestHandler !== "function") {
      return self.fail();
    }

    requestHandler();
  }
};

SpidStrategy.prototype.logout = function(req, callback) {
  const spidOptions = this.spidOptions.sp;

  const entityID = req.query.entityID;
  if (entityID !== undefined) {
    const idp = this.spidOptions.idp[entityID];
    spidOptions.entryPoint = idp.entryPoint;
    spidOptions.cert = idp.cert;
  }

  const samlClient = new saml(spidOptions);

  samlClient.getLogoutUrl(req, callback);
};

SpidStrategy.prototype.generateServiceProviderMetadata = function(
  decryptionCert
) {
  const spidOptions = this.spidOptions.sp;
  const samlClient = new saml(spidOptions);

  const metadata = {
    'EntityDescriptor' : {
      '@xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
      '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
      '@entityID': spidOptions.issuer,
      '@ID': spidOptions.issuer.replace(/\W/g, '_'),
      'SPSSODescriptor' : {
        '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@AuthnRequestsSigned': true,
        '@WantAssertionsSigned': true,
      },
    }
  };

  if (spidOptions.decryptionPvk) {
    if (!decryptionCert) {
      throw new Error(
        "Missing decryptionCert while generating metadata for decrypting service provider");
    }

    decryptionCert = decryptionCert.replace( /-+BEGIN CERTIFICATE-+\r?\n?/, '' );
    decryptionCert = decryptionCert.replace( /-+END CERTIFICATE-+\r?\n?/, '' );
    decryptionCert = decryptionCert.replace( /\r\n/g, '\n' );

    metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor = {
      'ds:KeyInfo' : {
        'ds:X509Data' : {
          'ds:X509Certificate': {
            '#text': decryptionCert
          }
        }
      },
      'EncryptionMethod' : [
        // this should be the set that the xmlenc library supports
        { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' },
        { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' },
        { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' }
      ]
    };
  }

  if (spidOptions.logoutCallbackUrl) {
    metadata.EntityDescriptor.SPSSODescriptor.SingleLogoutService = {
      '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@Location': spidOptions.logoutCallbackUrl
    };
  }

  metadata.EntityDescriptor.SPSSODescriptor.NameIDFormat = spidOptions.identifierFormat;
  metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService = {
    '@index': '1',
    '@isDefault': 'true',
    '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    '@Location': samlClient.getCallbackUrl({})
  };

  metadata.EntityDescriptor.Signature = {
    'SignedInfo': {
      'CanonicalizationMethod': {
        '@Algorithm': 'http://www.w3.org/2001/10/xml-exc-c14n#',
        'SignatureMethod': {
          '@Algorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        },
        'Reference': {
          '@URI': '#pfx9a8ea5db-ce3e-1f1d-ff15-c9b01ee53b32'
        }
      }
    }
  };

//   ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
//     <ds:SignedInfo>
//   <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
//     <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
//     <ds:Reference URI="#pfx9a8ea5db-ce3e-1f1d-ff15-c9b01ee53b32">
//     <ds:Transforms>
//   <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
//     <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
//     </ds:Transforms>
//     <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
//     <ds:DigestValue>2Q/XUND+wHPnu97OW6jW55Oq/NBxCkVgNxnxaYACSP4=</ds:DigestValue>
// </ds:Reference>
// </ds:SignedInfo>
//   <ds:SignatureValue>
//     k+Di49omADHqK6hIOFVQiYRfAfoLtQP2KM3J+d6qTqA3vENaklMKMPo5v3XMwghtF1DcFOBv33X7Zf1XAp4XqbjIaqXv5nap2cOZm2prWHO3pl4RAXjMff+8pBYs1IzFKXjh+MOjhPfLy7DgTIzEFStYymv0yDm+W2DaQwU+P3n+PQI3xaPCwHsgLy0xXZdBZ1MEQSiOSMhIHUokacVQ2F5QYHgQ+CgVovZWJUktJMH8X6Bb/DMK7cAd+0bn+cMLXAH9OgUI1vne9E7FVmu3O0oRlbvR+ehnGoQU6+vvn/CnhIjp87roJJspsQOoPpG8iSI1D2R/Dn2r23uHpK6xDhw=
//   </ds:SignatureValue>
//   <ds:KeyInfo>
//     <ds:X509Data>
//       <ds:X509Certificate>
//         MIIDczCCAlqgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBTMQswCQYDVQQGEwJpdDENMAsGA1UECAwEUm9tZTEUMBIGA1UECgwLYWdpZC5nb3YuaXQxHzAdBgNVBAMMFmh0dHBzOi8vaXRhbGlhLWJhY2tlbmQwHhcNMTcxMDI2MTAzNTQwWhcNMTgxMDI2MTAzNTQwWjBTMQswCQYDVQQGEwJpdDENMAsGA1UECAwEUm9tZTEUMBIGA1UECgwLYWdpZC5nb3YuaXQxHzAdBgNVBAMMFmh0dHBzOi8vaXRhbGlhLWJhY2tlbmQwggEjMA0GCSqGSIb3DQEBAQUAA4IBEAAwggELAoIBAgCXozdOvdlQhX2zyOvnpZJZWyhjmiRqkBW7jkZHcmFRceeoVkXGn4bAFGGcqESFMVmaigTEm1c6gJpRojo75smqyWxngEk1XLctn1+Qhb5SCbd2oHh0oLE5jpHyrxfxw8V+N2Hty26GavJE7i9jORbjeQCMkbggt0FahmlmaZr20akK8wNGMHDcpnMslJPxHl6uKxjAfe6sbNqjWxfcnirm05Jh5gYNT4vkwC1vx6AZpS2G9pxOV1q5GapuvUBqwNu+EH1ufMRRXvu0+GtJ4WtsErOakSF4KMezrMqKCrVPoK5SGxQMD/kwEQ8HfUPpim3cdi3RVmqQjsi/on6DMn/xTQIDAQABo1AwTjAdBgNVHQ4EFgQULOauBsRgsAudzlxzwEXYXd4uPyIwHwYDVR0jBBgwFoAULOauBsRgsAudzlxzwEXYXd4uPyIwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQIAQOT5nIiAefn8FAWiVYu2uEsHpxUQ/lKWn1Trnj7MyQW3QA/jNaJHL/EpszJ5GONOE0lVEG1on35kQOWR7qFWYhH9Llb8EAAAb5tbnCiA+WIx4wjRTE3CNLulL8MoscacIc/rqWf5WygZQcPDX1yVxmK4F3YGG2qDTD3fr4wPweYHxn95JidTwzW8Jv46ajSBvFJ95CoCYL3BUHaxPIlYkGbJFjQhuoxo2XM4iT6KFD4IGmdssS4NFgW+OM+P8UsrYi2KZuyzSrHq5c0GJz0UzSs8cIDC/CPEajx2Uy+7TABwR4d20Hyo6WImIFJiDanROwzoG0YNd8aCWE8ZM2y81Ww=
//       </ds:X509Certificate>
//     </ds:X509Data>
//   </ds:KeyInfo>
// </ds:Signature>

  // metadata.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  // signer = crypto.createSign('RSA-SHA256');
  // signer.update(querystring.stringify(metadata));
  // metadata.Signature = signer.sign(spidOptions.privateCert, 'base64');

  return xmlbuilder.create(metadata).end({ pretty: true, indent: '  ', newline: '\n' });
};

module.exports = SpidStrategy;
