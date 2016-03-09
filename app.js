'use strict';

var courier = {};

var express = require('express');
var sessions = require('client-sessions');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var csrf = require('csurf');

var app = express();

var sessionConfig = {
  cookieName: 'session',
  secret: 'whiu3112Ncwjie32ehwnefqhGUuguegue',
  duration: 30 * 60 * 100,
  activeDuration: 5 * 60 * 100
};
// connect to mongo
mongoose.connect('mongodb://localhost/newauth');

var Schema = mongoose.Schema;
var _id = Schema.ObjectId;
var userSchema = {
  id: _id,
  firstName: String,
  lastName: String,
  email: {
    type: String,
    unique: true
  },
  password: String,
};
var objectSchema = new Schema(userSchema);

var User = mongoose.model('User', objectSchema);


// Middleware
var urlencodedConfig = { extended: true };
var bodyParserMiddleware = bodyParser.urlencoded(urlencodedConfig);
var sessionsMiddleware = sessions(sessionConfig);

app.use(bodyParserMiddleware);
app.use(sessionsMiddleware);
app.use(interrupt);
app.use(csrf());

function interrupt(req, res, next) {
  courier.interrupt = {
    req: req,
    res: res,
    next: next
  };
  if (req.session && req.session.user) {
    return User.findOne(_checker(req.body.email), _sessionAssign);
  }
  return next();
}

function _sessionAssign(err, userData) {
  if (userData){
    delete userData.password;
    courier.interrupt.req.session.user = userData;
    courier.interrupt.res.locals.user = userData;
  }
  return courier.interrupt.next();
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  return next();
}

app.set('view engine', 'jade');
app.get('/', indexGet);
app.get('/register', registerGet);
app.post('/register', registerPost);
app.get('/login', loginGet);
app.post('/login', loginPost);
app.get('/dashboard', requireLogin, dashboardGet);
app.get('/logout', logout);

function indexGet(req, res) {
  return res.render('index.jade');
}

function registerGet(req, res) {
  return res.render('register.jade', csrfToken(req));
}

function registerPost(req, res) {
  var insertedValue = {
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10))
  };
  var user = new User(insertedValue);
  courier.registerPost = {
    req: req,
    res: res,
  };
  return user.save(_registerHandler);
}

function _registerHandler(err, userData) {
  if (err) {
    var error = {
      errMsg: (err.code === 11000) ? 'Email already taken' : 'Something bad happen. Go Masturbate!'
    }

    return courier.registerPost.res.render('register.jade', error);
  }

  courier.registerPost.req.session.user = userData;
  return courier.registerPost.res.redirect('/dashboard');
}

function loginGet(req, res) {
  return res.render('login.jade', csrfToken(req));
}

function loginPost(req, res) {
  courier.loginPost = {
    req: req,
    body: req.body,
    res: res
  };
  return User.findOne(_checker(req.body.email), _loginHandler);
}

function _loginHandler(err, userData) {
  if (!userData) {
    return _errorRender('Invalid email');
  }

  if (bcrypt.compareSync(courier.loginPost.body.password, userData.password)) {
    courier.loginPost.req.session.user = userData;
    return courier.loginPost.res.redirect('/dashboard');
  }
  return _errorRender('Invalid password');
}

function _errorRender(argument) {
  return courier.loginPost.res.render('login.jade', {error: argument});
}

function dashboardGet(req, res) {
  return res.render('dashboard.jade', {user: req.session.user});
}

function _checker(email) {
  return {
    email: email
  };
}

function csrfToken(req) {
  return {
    csrfToken: req.csrfToken()
  };
}

function logout(req, res) {
  req.session.reset();
  return res.redirect('/');
}

app.listen(3000);