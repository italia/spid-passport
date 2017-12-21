const fs = require('fs')
const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const passport = require('passport')
const SpidStrategy = require('../index')


app.use(bodyParser.urlencoded({ extended: false }))

// parse application/json
app.use(bodyParser.json())

// init passport
app.use(passport.initialize())

let spidStrategy = new SpidStrategy({
  sp: {
    path: "/acs",
    issuer: "http://issuer-name",
    privateCert: fs.readFileSync("./certs/key.pem", "utf-8"),
    attributeConsumingServiceIndex: 1,
    identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    authnContext: "https://www.spid.gov.it/SpidL1"
  },
  idp: {
    test: {
      entryPoint: "https://spid-testenv-identityserver:9443/samlsso",
      cert: "MIICNTCCAZ6gAwIBAgIES343gjANBgkqhkiG9w0BAQUFADBVMQswCQYD..."
    }
  }
}, function(profile, done){

  // Find or create your user
  console.log('all done!!!!!', profile)
  done()
})

 passport.use(spidStrategy)

app.get("/login", passport.authenticate('spid'))

app.post("/acs",
  passport.authenticate('spid', {session: false}),
  function(req, res){
    console.log(req.user)
    res.send(`Hello ${req.user.name_id}`)
  })

// Create xml metadata
app.get("/metadata", spidStrategy.createMetadata())


app.listen(3000);