"use strict";

var express = require('express');

var path = require('path');

var dotEnv = require('dotenv');

var morgan = require('morgan');

var chalk = require('chalk');

var session = require('express-session');

var MongoStore = require('connect-mongo')(session);

var passport = require('passport');

var bcrypt = require('bcryptjs');

var mongoose = require('mongoose');

var User = require('./models/user');

var multer = require('multer'); // const cloudinary = require('cloudinary').v2;

/* eslint-disable */


dotEnv.config({
  path: path.join(__dirname, 'config', 'config.env')
}); // Place the "L" after the "UR"

var dbURL = process.env.MONGO_UR || process.env.LOCAL_DB;
var PORT = process.env.PORT || 3000;
mongoose.connect(dbURL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false
}).then(function (db) {
  console.log(chalk.bgCyan.white.bold("\n      server is connected with database: ".concat(db.connections[0].name, " and \n      host: ").concat(db.connections[0].host, " on\n      port:  ").concat(db.connections[0].port, " ")));
})["catch"](function (err) {
  return console.log(err.message);
});
mongoose.connection.once('open', function (err) {
  if (err) {
    console.log(err);
  } else {
    console.log(chalk.white.bgRed.bold('Mongoose is Successfully Connected'));
  }
});
mongoose.connection.on('error', function (err) {
  if (err) {
    console.log(err);
  } else {
    console.log('Mongoose is Successfully Connected');
  }
});

require('./services/LocalAuth')(passport);

require('./services/GoogleAuth')(passport);

var app = express(); // FILE UPLOADS

var storage = multer.diskStorage({
  destination: function destination(req, file, cb) {
    cb(null, './uploads/');
  },
  filename: function filename(req, file, cb) {
    cb(null, new Date().toISOString() + file.originalname);
  }
});

var fileFilter = function fileFilter(req, file, cb) {
  if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/jpg' || file.mimetype === 'image/png' || file.mimetype === 'image/svg') {
    cb(null, true);
  } else {
    cb(null, false);
  }
};

var upload = multer({
  storage: storage,
  limits: {
    fieldSize: 1024 * 1024 * 5 // 5MB

  },
  fileFilter: fileFilter
}); // MIDDLEWARES

app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));
app.use('/uploads', express["static"]('uploads'));
/* eslint-disable */

app.use(express["static"](path.join(__dirname, 'public'))); // If enabled, be sure to use session() before passport.session() to ensure that the login session is restored in the correct order.

app.use(session({
  secret: 'Younis & Waqas',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 2 * 60 * 60 * 1000
  },
  store: new MongoStore({
    mongooseConnection: mongoose.connection
  })
}));
app.use(passport.initialize());
app.use(passport.session()); // FOr Dev Environment

if (process.env.NODE_ENV) {
  app.use(morgan('dev'));
}

app.use(function (req, res, next) {
  res.locals.user = req.user;
  next();
}); // ======================== Here goes "index.js" Route =============================

app.use('/', require('./routes/index'));
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile']
})); // @desc   google auth callback
// @route  GET /auth/google/callback

app.get('/auth/google/callback', passport.authenticate('google', {
  failureRedirect: '/'
}), function (req, res) {
  res.redirect('/');
});
app.post('/register', function (req, res) {
  console.log(req.body);
  bcrypt.genSalt(10, function (err, salt) {
    bcrypt.hash(req.body.password, salt, function (err, hash) {
      if (err) {
        console.log(err);
        res.send(err);
      } else {
        var user = {
          username: req.body.username,
          password: hash
        };
        User.create(user, function (err, user) {
          if (err) {
            console.log(err);
          } else {
            console.log(user);
            res.redirect('/login');
          }
        });
      }
    });
  });
});
app.get('/login', function (req, res) {
  res.render('login');
});
app.post('/login', passport.authenticate('local', {
  failureRedirect: '/login'
}), function (req, res) {
  res.redirect('/');
});
app.get('/secret', isAuthenticated, function (req, res) {
  res.render('secret');
});
app.get('/logout', function (req, res) {
  req.logout();
  res.redirect('/');
});
app.post('/fileUploads', upload.single('file'), function (req, res) {
  if (req.file) {
    console.log('File Submitted', req.file.path);
    res.send('File Submitted');
  } else {
    res.send('Something went wrong');
  }
});

function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();else {
    res.redirect('/');
  }
}

app.listen(PORT, function () {
  return console.log(chalk.white.bgMagenta.bold('server is running at http://localhost:3000'));
});