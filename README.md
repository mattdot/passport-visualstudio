# passport-visualstudio [![Build Status](https://travis-ci.org/mattdot/passport-visualstudio.svg?branch=master)](https://travis-ci.org/mattdot/passport-visualstudio)

[Passport](http://passportjs.org/) strategy for authenticating with [Visual Studio Online](http://www.visualstudio.com/)
using the OAuth 2.0 API.

This module lets you authenticate using Visual Studio Online in your Node.js applications.
By plugging into Passport, Facebook authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-visualstudio

## Usage

#### Create an Application

Before using `passport-visualstudio`, you must register an application with
Visual Studio Online.  If you have not already done so, a new application can be created at
[Visual Studio Extensions](https://app.vssps.visualstudio.com/app/register).  Your application will
be issued an app ID and app secret, which need to be provided to the strategy.
You will also need to configure a redirect URI which matches the route in your
application.

#### Configure Strategy

The VisualStudio authentication strategy authenticates users using a VisualStudio
account and OAuth 2.0 tokens.  The app ID and secret obtained when creating an
application are supplied as options when creating the strategy.  The strategy
also requires a `verify` callback, which receives the access token and optional
refresh token, as well as `profile` which contains the authenticated user's
Facebook profile.  The `verify` callback must call `cb` providing a user to
complete authentication.

```js
passport.use(new VisualStudioStrategy({
    clientID: VSO_APP_ID,
    clientSecret: VSO_APP_SECRET,
    callbackURL: "https://localhost:3000/auth/visualstudio/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ visualStudioId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'visualstudio'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```js
app.get('/auth/visualstudio',
  passport.authenticate('visualstudio'));

app.get('/auth/visualstudio/callback',
  passport.authenticate('visualstudio', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```
