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

  // Find or create your user
  console.log('all done!!!!!', profile)
  done()
})

 passport.use('Spid', spidStrategy)

app.get("/login", passport.authenticate('Spid'))

app.post("/assert",
  passport.authenticate('Spid', {session: false}),
  function(req, res){
    console.log(req.user)
    res.send(`Hello ${req.user.name_id}`)
  })

// Create xml metadata
app.get("/metadata", spidStrategy.createMetadata())


app.listen(3000);