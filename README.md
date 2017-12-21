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
Sono necessari i parametri di configurazione per l'Identity Provider e per i diversi Service Provider e nello specifico il costruttore prende in input due oggetti e una callback di verifica:

##### Service Provider: 
- (String) `issuer` - Nome entita che fornisce il servizio
- (String) `privateCert` - Chiave privata del Service Provider (Formato PEM)
- (String) `path` - Endpoint sul quale ricevere la response dall'identity provider
- (String) `attributeConsumingServiceIndex` - Indice posizionale sul metadata che identifica il set di attributi richiesti all'Identity Provider
- (String) `identifierFormat` - Formato dell'identificativo dell'utente
- (String) `authnContext` - Livello SPID richiesto (ad es.: https://www.spid.gov.it/SpidL1)

##### Identity Provider

- (String) `entryPoint` - Endpoint per effettuare il login, verra effettuato un redirect
- (String) `cert` - Certificati dell' Identity Provider (Formato PEM)


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
    path: "/acs",
    issuer: "http://italia-backend",
    privateCert: fs.readFileSync("./certs/key.pem", "utf-8"),
    attributeConsumingServiceIndex: 1,
    identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    authnContext: "https://www.spid.gov.it/SpidL1"
  },
  idp: {
    entryPoint: "https://spid-testenv-identityserver:9443/samlsso",
    cert: "MIICNTCCAZ6gAwIBAgIES343gjANBgkqhkiG9w0BAQUFADBVMQswCQYD..."
  }
}, function(profile, done){

  // Find or create user
  console.log(profile)
  done()
})

passport.use(spidStrategy)

app.get("/login", passport.authenticate('spid'))

app.post("/assert",
  passport.authenticate('spid', {session: false}),
  function(req, res){
    console.log(req.user)
    res.send(`Hello ${req.user.name_id}`)
  })

// Create xml metadata
app.get("/metadata", spidStrategy.createMetadata())


app.listen(3000);
```
