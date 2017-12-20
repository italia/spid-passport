# spid-passport
Passport authentication provider for SPID

Questo modulo consente di autenticare i vostri utenti tramite Spid (Servizio Publico per L'Identificazione Digitale) 
nella vostra app nodejs

## Installazione

``` bash
$ npm install spid-passport
```

## Utilizzo
### Configurazione
Sono necessari i parametri di configurazione per l'Identity Provider e per il Service Provider e nello specifico il costruttore prende in input due oggetti e una callback di verifica:

##### Service Provider: 
- (String) `entity_id` - Nome entita che fornisce il servizio
- (Stirng) `private_key` - Chiave privata del Service Provider (Formato PEM)
- (String) `certificate` - Certificato Service Provider (Formato PEM)
- (String) `assert_endpoint` - Endpoint sul quale ricevere la response dall'identity provider

##### Identity Provider

- (String) `sso_login_url` - Endpoint per effettuare il login, verra effettuato un redirect
- (String) `sso_logout_url` - Endpoint per effettuare il logout
- (String) `certifates` - Certificati dell' Identity Provider (Formato PEM)


## Esempio di utilizzo con express e spid-test-env
```javascript
const fs = require('fs')
const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const passport = require('passport')
const SpidStrategy = require('passport-spid')


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

  // Find or create user
  console.log(profile)
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
```
