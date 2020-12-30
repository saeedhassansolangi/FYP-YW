const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('home');
});

router.get('/contact', (req, res) => {
  res.send('Hello WOrld');
});

router.get('/register', (req, res) => {
  res.render('register');
});

module.exports = router;
