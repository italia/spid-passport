'use strict';
const util = require('util');
var Strategy = require('passport-strategy');
const saml2 = require('saml2-js');
const ServiceProvider = saml2.ServiceProvider;
const IdentityProvider =  saml2.IdentityProvider;

/**
 *
 * @constructor
 * @param {Object} sp oggetto di configurazione del service provider
 * @param {String} sp.entity_id service provider entity_id
 * @param {String} sp.private_key path della chiave privata del service provider
 * @param {String} sp.crt path del certificato del service provider
 * @param {String} sp.assert_endpoint endopint per recevere la risposta dall' idp
 * @param {String} sp.assert_endpoint endopint per recevere la risposta dall' idp
 * @param {Object} idp oggetto di conf dell' identity provider
 * @param {String} idp.sso_login_url url login
 * @param {String} idp.sso_logout_url url logout
 * @param {String []} idp.certificates array di path dei certificati
 * @param {String} idp oggetto di conf dell' identity provider
 *
 */
function SpidStrategy(sp, idp) {

    // params check
    if (!sp || !sp.entity_id || !sp.private_key || !sp.crt || !sp.assert_endpoint) {
        throw new Error("Invalid service provider params");
    }
    if (!idp || !idp.sso_login_url || !idp.sso_logout_url || !idp.certificates) {
        throw new Error("Invalid identity provider params");
    }

    const spcfg = {
        entity_id: sp.entity_id,
        private_key: fs.readFileSync(sp.private_key).toString(),
        certificate: fs.readFileSync(sp.crt).toString(),
        assert_endpoint: sp.assert_endpoint,
        force_authn: false,
        allow_unencrypted_assertion: true,
        auth_context: {comparison: "exact", class_refs: ["urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1"]}
    };

    const idpcfg = {
        sso_login_url: idp.sso_login_url,
        allow_unencrypted_assertion: true,
        sso_logout_url: idp.sso_logout_url,
        certificates: Array.isArray(idp.certificates) ? idp.certificates.map((item) => {
            return fs.readFileSync(item).toString();
        }) : idp.certificates
    };

    this.ServiceProvider = new ServiceProvider(spcfg);
    this.IdentityProvider = new IdentityProvider(idpcfg);
    Strategy.call(this);
}


SpidStrategy.prototype.authenticate = function(req, options) {

}
util.inherits(SpidStrategy, Strategy);