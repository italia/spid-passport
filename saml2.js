'use strict'
var saml2 = require('saml2-js');
var fs = require('fs');
var express = require('express');
var app = express();
var bodyParser = require('body-parser')
app.use(bodyParser.urlencoded({ extended: false }))

var passport = require('passport')
var SpidStrategy = require('./index')


// parse application/json
app.use(bodyParser.json())

app.use(passport.initialize())

var spidStrategy = new SpidStrategy({
    sp: {
        entity_id: 'hackdev',
        private_key: fs.readFileSync("./certs/key.pem").toString(),
        certificate: fs.readFileSync("./certs/cert.pem").toString(),
        assert_endpoint: "http://hackdev.it:3000/assert",
    },
    idp: {
        sso_login_url: "https://spid-testenv-identityserver:9443/samlsso",
        sso_logout_url: "https://spid-testenv-identityserver:9443/samlsso",
        certificates: fs.readFileSync("./certs/idp.certificate.crt").toString()
    }
}, function(profile, done){
    console.log('all done!!!!!', profile)
    done()
})


passport.use('Spid', spidStrategy)

app.get("/login", passport.authenticate('Spid'));


app.get("/metadata", spidStrategy.createMetadata());


// Assert endpoint for when login completes
app.post("/assert",
    passport.authenticate('Spid', {session: false}),
    function(req, res){
        console.log(req.user)
        res.send(`Hello ${req.user.name_id}`)
    })


function test(req, res) {

    return res.send('Hello');


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
}

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