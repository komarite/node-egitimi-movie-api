const express = require('express');
const router = express.Router();

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

//Models
const User = require('../models/Users')

/* GET home page. */
router.get('/', (req, res, next) => {
  res.render('index', { title: 'Express' });
});

router.post('/register', (req, res, next) => {
  const { username, password } = req.body;

  bcrypt.hash(password, 10).then((hash) => {
    const user = new User({
      username,
      password: hash
    });

    const promise = user.save();
    promise.then((data) => {
      res.json(data)
    }).catch((err) => {
      res.json(err);
    })
  })

});

router.post('/authenticate', async (req, res, next) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (!user) {
      res.json({
        status: false,
        message: 'Authentication failed, user not found.'
      });
    } else {
      const result = await bcrypt.compare(password, user.password);

      if (!result) {
        res.json({
          status: false,
          message: 'Authentication failed, wrong password'
        });
      } else {
        const payload = {
          username
        };
        const token = jwt.sign(payload, req.app.get('api_secret_key'), {
          expiresIn: 720 //12saat
        });

        res.json({
          status: true,
          token
        });
      }
    }
  } catch (err) {
    throw err;
  }
});


module.exports = router;
