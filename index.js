const passport = require("passport-strategy");
const util = require("util");
var xmlCrypto = require("xml-crypto");
var xmlbuilder = require("xmlbuilder");
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
  } else {
    // Do a check against all IDP certs if we don't have an entityID
    const idps = this.spidOptions.idp;
    spidOptions.cert = Object.keys(idps).map(k => idps[k].cert);
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
    EntityDescriptor: {
      "@xmlns": "urn:oasis:names:tc:SAML:2.0:metadata",
      "@xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
      "@entityID": spidOptions.issuer,
      "@ID": spidOptions.issuer.replace(/\W/g, "_"),
      SPSSODescriptor: {
        "@protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@AuthnRequestsSigned": true,
        "@WantAssertionsSigned": true
      }
    }
  };

  if (spidOptions.decryptionPvk) {
    if (!decryptionCert) {
      throw new Error(
        "Missing decryptionCert while generating metadata for decrypting service provider"
      );
    }

    decryptionCert = decryptionCert.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, "");
    decryptionCert = decryptionCert.replace(/-+END CERTIFICATE-+\r?\n?/, "");
    decryptionCert = decryptionCert.replace(/\r\n/g, "\n");

    metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor = {
      "ds:KeyInfo": {
        "ds:X509Data": {
          "ds:X509Certificate": {
            "#text": decryptionCert
          }
        }
      },
      EncryptionMethod: [
        // this should be the set that the xmlenc library supports
        { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#aes256-cbc" },
        { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#aes128-cbc" },
        { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#tripledes-cbc" }
      ]
    };
  }

  if (spidOptions.logoutCallbackUrl) {
    metadata.EntityDescriptor.SPSSODescriptor.SingleLogoutService = {
      "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      "@Location": spidOptions.logoutCallbackUrl
    };
  }

  metadata.EntityDescriptor.SPSSODescriptor.NameIDFormat =
    spidOptions.identifierFormat;
  metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService = {
    "@index": spidOptions.attributeConsumingServiceIndex,
    "@isDefault": "true",
    "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "@Location": samlClient.getCallbackUrl({})
  };

  if (spidOptions.attributes) {
    function getFriendlyName(name) {
      const friendlyNames = {
        name: "Nome",
        familyName: "Cognome",
        fiscalNumber: "Codice fiscale",
        email: "Email"
      };

      return friendlyNames[name];
    }

    const attributes = spidOptions.attributes.attributes.map(function(item) {
      return {
        "@Name": item,
        "@NameFormat":
          "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
        "@FriendlyName": getFriendlyName(item)
      };
    });

    metadata.EntityDescriptor.SPSSODescriptor.AttributeConsumingService = {
      "@index": spidOptions.attributeConsumingServiceIndex,
      ServiceName: {
        "@xml:lang": "it",
        "#text": spidOptions.attributes.name
      },
      RequestedAttribute: attributes
    };
  }

  if (spidOptions.organization) {
    metadata.EntityDescriptor.Organization = {
      OrganizationName: spidOptions.organization.name,
      OrganizationDisplayName: spidOptions.organization.displayName,
      OrganizationURL: spidOptions.organization.URL
    };
  }

  const xml = xmlbuilder.create(metadata).end({
    pretty: true,
    indent: "  ",
    newline: "\n"
  });

  function MyKeyInfo(file) {
    this.file = file;

    this.getKeyInfo = function(key, prefix) {
      prefix = prefix || "";
      prefix = prefix ? prefix + ":" : prefix;
      return (
        "<" +
        prefix +
        "X509Data><X509Certificate>" +
        decryptionCert +
        "</X509Certificate></" +
        prefix +
        "X509Data>"
      );
    };

    this.getKey = function(keyInfo) {
      return this.file;
    };
  }

  var sig = new xmlCrypto.SignedXml();
  sig.signingKey = spidOptions.privateCert;
  sig.keyInfoProvider = new MyKeyInfo(decryptionCert);
  sig.addReference(
    "//*[local-name(.)='EntityDescriptor']",
    [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#"
    ],
    "http://www.w3.org/2001/04/xmlenc#sha256"
  );
  sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  sig.computeSignature(xml);

  return sig.getSignedXml();
};

module.exports = SpidStrategy;
