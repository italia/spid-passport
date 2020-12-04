# ⚠️ Questo repository non è più mantenuto, si consiglia di usare [spid-express](https://github.com/italia/spid-express) ⚠️

# spid-passport
Provider di autenticazione Passport per SPID

Questo modulo consente di autenticare gli utenti tramite SPID (Servizio Publico di Identità Digitale) 
nelle applicazioni Nodejs che fanno uso di [Passport](http://www.passportjs.org).

## Installazione

``` bash
$ npm install spid-passport
```

## Utilizzo
### Configurazione
Sono necessari i parametri di configurazione del Service Provider e dei
diversi Identity Provider; nello specifico il costruttore prende in input
due oggetti e una callback di verifica.
Le opzioni possibili sono tutte quelle messe a disposizione dalla libreria
[passport-saml](https://github.com/bergie/passport-saml#config-parameter-details),
con l'unica differenza che i parametri relativi agli Identity Provider sono
ripetuti per ciascun Identity Provider supportato da SPID. I parametri obbligatori sono:

##### Service Provider: 
- (String) `issuer` - Id dell'entita che fornisce il servizio, può essere qualsiasi cosa, tipicamente è la URL del Service Provider
- (String) `privateCert` - Chiave privata del Service Provider (Formato PEM)
- (String) `path` - Endpoint sul quale ricevere la response dall'identity provider; viene combinata con le informazioni dell'host per costruire una url completa
- (Number) `attributeConsumingServiceIndex` - Indice posizionale sul metadata che identifica il set di attributi richiesti all'Identity Provider
- (String) `identifierFormat` - Formato dell'identificativo dell'utente, per SPID va valorizzato a `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`
- (String) `authnContext` - Livello SPID richiesto (a scelta tra: https://www.spid.gov.it/SpidL1, https://www.spid.gov.it/SpidL2, https://www.spid.gov.it/SpidL3)

##### Identity Provider

- (String) `entryPoint` - Endpoint per effettuare il login, verrà effettuato un redirect verso questa URL
- (String) `cert` - Certificato dell'Identity Provider (Formato PEM)


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
    callbackUrl: "https://example.com/acs",
    issuer: "https://example.com",
    privateCert: fs.readFileSync("./certs/key.pem", "utf-8"),
    decryptionPvk: fs.readFileSync("./certs/key.pem", "utf-8"),
    attributeConsumingServiceIndex: 1,
    identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    authnContext: "https://www.spid.gov.it/SpidL1"
    attributes: {
      name: "Required attributes",
      attributes: ["fiscalNumber", "name", "familyName", "email"]
    },
    organization: {
      name: "Organization name",
      displayName: "Organization display name",
      URL: "https://example.com"
    }
  },
  idp: {
    test: {
      entryPoint: "https://spid-testenv-identityserver:9443/samlsso",
      cert: "MIICNTCCAZ6gAwIBAgIES343gjANBgkqhkiG9w0BAQUFADBVMQswCQYD..."
    },
    idp2: {
      entryPoint: "https://...",
      cert: "..."
    }
  }
}, function(profile, done){

  // Find or create user
  console.log(profile)
  done(null, profile);
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
app.get("/metadata", spidStrategy.generateServiceProviderMetadata())


app.listen(3000);
```
