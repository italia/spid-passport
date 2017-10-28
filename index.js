'use strict';
const util = require('util');
var Strategy = require('passport-strategy');
const saml2 = require('saml2-js');
const ServiceProvider = saml2.ServiceProvider;
const IdentityProvider =  saml2.IdentityProvider;

/**
 *
 * @constructor
 *
 * @param {Object} options Oggetto con la configurazione
 * @param {Object} options.sp oggetto di configurazione del service provider
 * @param {String} sp.entity_id service provider entity_id
 * @param {String} sp.private_key path della chiave privata del service provider
 * @param {String} sp.certificate certificato del service provider
 * @param {String} sp.assert_endpoint endopint per recevere la risposta dall' idp
 * @param {String} sp.assert_endpoint endopint per recevere la risposta dall' idp
 * @param {Object} options.idp oggetto di conf dell' identity provider
 * @param {String} options.idp.sso_login_url url login
 * @param {String} options.idp.sso_logout_url url logout
 * @param {String []} options.idp.certificates array di path dei certificati
 * @param {String} idp oggetto di conf dell' identity provider
 *
 */
function SpidStrategy(options, verify) {
    if(!options){
        throw new Error('Options required')
    }

    if(typeof options === 'function'){
        throw new Error('Options is required')
    }

    // params check
    let sp = options.sp
    if (!sp || !sp.entity_id || !sp.private_key || !sp.certificate || !sp.assert_endpoint) {
        throw new Error('Spid Strategy require Service Provider configuration');
    }

    let idp = options.idp
    if (!idp || !idp.sso_login_url || !idp.sso_logout_url || !idp.certificates) {
        throw new Error('Spid Strategy require Identity Provider configuration');
    }

    Strategy.call(this);
    const spcfg = {
        entity_id: sp.entity_id,
        private_key: sp.private_key,
        certificate: sp.certificate,
        assert_endpoint: sp.assert_endpoint,
        force_authn: false,
        allow_unencrypted_assertion: true,
        auth_context: {comparison: "exact", class_refs: ["urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1"]}
    };

    const idpcfg = {
        sso_login_url: idp.sso_login_url,
        allow_unencrypted_assertion: true,
        sso_logout_url: idp.sso_logout_url,
        certificates: idp.certificates
    };

    this.ServiceProvider = new ServiceProvider(spcfg)
    this.IdentityProvider = new IdentityProvider(idpcfg)
    this.verify = verify
}

util.inherits(SpidStrategy, Strategy);


SpidStrategy.prototype.authenticate = function(req, options) {
    let _options
    var self = this

    if(req.body && req.body.SAMLResponse){

        this.ServiceProvider.post_assert(self.IdentityProvider, {
            request_body: req.body,
            require_session_index: false,
        }, function(err, samlRespone) {

            if(err !== null){
                return self.fail(err.message)
            }
            let user = samlRespone.user
            self.verify(user, function(err){
                err ? self.fail(err) : self.success(user)
            })
        })
    }
    else {
        this.ServiceProvider.create_login_request_url(self.IdentityProvider, {}, function (err, loginUrl, requestId) {
            err ? self.fail(err, 500) : self.redirect(loginUrl)
        })
    }
}



SpidStrategy.prototype.createMetadata = function(){
    var sp = this.ServiceProvider;
    return function(req, res, next) {
        res.type('application/xml')
        res.send(sp.create_metadata())
    }
}

module.exports = SpidStrategy