const express = require('express');
const path = require('path');
const dotEnv = require('dotenv');
const morgan = require('morgan');
const chalk = require('chalk');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('./models/user');
const multer = require('multer');

/* eslint-disable */
dotEnv.config({ path: path.join(__dirname, 'config', 'config.env') });

const dbURL = process.env.MONGO_URL || process.env.LOCAL_DB;

mongoose
  .connect(dbURL, {
    useUnifiedTopology: true,
    useNewUrlParser: true,
  })
  .then((db) => {
    console.log(
      chalk.bgCyan.white.bold(`
      server is connected with database: ${db.connections[0].name} and 
      host: ${db.connections[0].host} on
      port:  ${db.connections[0].port} `)
    );
  })
  .catch((err) => console.log(err.message));

mongoose.connection.once('open', (err) => {
  if (err) {
    console.log(err);
  } else {
    console.log(chalk.white.bgRed.bold('Mongoose is Successfully Connected'));
  }
});

mongoose.connection.on('error', (err) => {
  if (err) {
    console.log(err);
  } else {
    console.log('Mongoose is Successfully Connected');
  }
});

passport.use(
  new LocalStrategy(function (username, password, done) {
    User.findOne({ username: username }, function (err, user) {
      if (err) {
        console.log('!done');
        return done(err);
      }

      if (!user) {
        console.log('!done');
        return done(null, false, { message: 'Incorrect username.' });
      }

      if (!user.password === password) {
        console.log('!done');
        return done(null, false, { message: 'Incorrect password.' });
      }

      bcrypt
        .compare(user.password, password)
        .then((res) => {
          // res === true
          console.log('done');
          return done(null, user);
        })
        .catch((err) => console.log(err));
    });
  })
);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

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
    fieldSize: 1024 * 1024 * 5,
  },
  fileFilter: fileFilter,
});

// var upload = multer({ dest: 'uploads/' });

// MIDDLEWARES
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* eslint-disable */
app.use(express.static(path.join(__dirname, 'public')));

// If enabled, be sure to use session() before passport.session() to ensure that the login session is restored in the correct order.
app.use(
  session({
    secret: 'Younis & Waqas',
    resave: false,
    saveUninitialized: true,
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

/* eslint-enable */
app.get('/', (req, res) => {
  res.render('home');
});

app.get('/contact', (req, res) => {
  res.send('Hello WOrld');
});

app.get('/register', (req, res) => {
  res.render('register');
});

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
            console.log('User is inserted in the Database');
            res.send(hash);
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
    res.render('secret');
  }
);

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

app.listen(3000, () =>
  console.log(
    chalk.white.bgMagenta.bold('server is running at http://localhost:3000')
  )
);
