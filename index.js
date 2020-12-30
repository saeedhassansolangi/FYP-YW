const express = require('express');
const path = require('path');
const dotEnv = require('dotenv');
const morgan = require('morgan');
const chalk = require('chalk');
const session = require('express-session');
const MongoStore = require('connect-mongo')(session);
const passport = require('passport');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('./models/user');
const multer = require('multer');
const connectDB = require('./config/db');
// const cloudinary = require('cloudinary').v2;

/* eslint-disable */
dotEnv.config({ path: path.join(__dirname, 'config', 'config.env') });
const PORT = process.env.PORT || 3000;
// Database Config
connectDB();

require('./services/LocalAuth')(passport);
require('./services/GoogleAuth')(passport);

const app = express();

// FILE UPLOADS
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, new Date().toISOString() + file.originalname);
  },
});

const fileFilter = (req, file, cb) => {
  if (
    file.mimetype === 'image/jpeg' ||
    file.mimetype === 'image/jpg' ||
    file.mimetype === 'image/png' ||
    file.mimetype === 'image/svg'
  ) {
    cb(null, true);
  } else {
    cb(null, false);
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fieldSize: 1024 * 1024 * 5, // 5MB
  },
  fileFilter: fileFilter,
});

// MIDDLEWARES
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

/* eslint-disable */
app.use(express.static(path.join(__dirname, 'public')));

// If enabled, be sure to use session() before passport.session() to ensure that the login session is restored in the correct order.
app.use(
  session({
    secret: 'Younis & Waqas',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 2 * 60 * 60 * 1000 },
    store: new MongoStore({ mongooseConnection: mongoose.connection }),
  })
);

app.use(passport.initialize());
app.use(passport.session());

// FOr Dev Environment
if (process.env.NODE_ENV) {
  app.use(morgan('dev'));
}

app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});

// ======================== Here goes "index.js" Route =============================

app.use('/', require('./routes/index'));

app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

// @desc   google auth callback
// @route  GET /auth/google/callback

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/');
  }
);

app.post('/register', (req, res) => {
  console.log(req.body);
  bcrypt.genSalt(10, function (err, salt) {
    bcrypt.hash(req.body.password, salt, function (err, hash) {
      if (err) {
        console.log(err);
        res.send(err);
      } else {
        const user = { username: req.body.username, password: hash };
        User.create(user, (err, user) => {
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

app.get('/login', (req, res) => {
  res.render('login');
});

app.post(
  '/login',
  passport.authenticate('local', { failureRedirect: '/login' }),
  function (req, res) {
    res.redirect('/');
  }
);

app.get('/secret', isAuthenticated, (req, res) => {
  res.render('secret');
});

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.post('/fileUploads', upload.single('file'), (req, res) => {
  if (req.file) {
    console.log('File Submitted', req.file.path);
    res.send('File Submitted');
  } else {
    res.send('Something went wrong');
  }
});

function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  else {
    res.redirect('/');
  }
}

app.listen(PORT, () =>
  console.log(
    chalk.white.bgMagenta.bold('server is running at http://localhost:3000')
  )
);
