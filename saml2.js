'use strict'
var saml2 = require('saml2-js');
var fs = require('fs');
var express = require('express');
var app = express();
var bodyParser = require('body-parser')
app.use(bodyParser.urlencoded({ extended: false }))

// parse application/json
app.use(bodyParser.json())
const ServiceProvider = saml2.ServiceProvider;
const IdentityProvider =  saml2.IdentityProvider;
const spcfg = {
    entity_id: 'hackdev',
    private_key: fs.readFileSync("./certs/key.pem").toString(),
    certificate: fs.readFileSync("./certs/cert.pem").toString(),
    assert_endpoint: "http://hackdev.it:3000/assert",
    force_authn: false,
    allow_unencrypted_assertion: true,
    auth_context: { comparison: "exact", class_refs: ["urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1"] }

}

const sp = new ServiceProvider(spcfg)

const idpcfg = {
    sso_login_url: "https://spid-testenv-identityserver:9443/samlsso",
    allow_unencrypted_assertion: true,
    sso_logout_url: "https://spid-testenv-identityserver:9443/samlsso",
    certificates: fs.readFileSync("./certs/idp.certificate.crt").toString()
}

const idp = new IdentityProvider(idpcfg)

app.get("/login", function(req, res) {
    sp.create_login_request_url(idp, {}, function(err, login_url, request_id) {

        //console.log(request_id, login_url)
        if (err != null)
            return res.send(500);
        res.redirect(login_url);
    });
});
app.get("/metadata", function(req, res) {
    res.type('application/xml');
    res.send(sp.create_metadata());
});
// Assert endpoint for when login completes
app.post("/assert", function(req, res) {
    var options = {
        request_body: req.body,
        require_session_index: false
    };

    sp.post_assert(idp, options, function(err, saml_response) {


        if (err != null)
            return res.send(err.message);

        // Save name_id and session_index for logout
        // Note:  In practice these should be saved in the user session, not globally.
        var name_id = saml_response.user.name_id;

        console.log(saml_response)
        res.send("Hello "+name_id+"!");
    });
});

// Starting point for logout
app.get("/logout", function(req, res) {
    var options = {
        name_id: name_id,
        session_index: session_index
    };

    sp.create_logout_request_url(idp, options, function(err, logout_url) {
        if (err != null)
            return res.send(500);
        res.redirect(logout_url);
    });
});

app.listen(3000);