const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const passport = require('passport');
var jwt = require('jsonwebtoken');

// load user model
require('../models/User');
const User = mongoose.model('users');

// user login route
router.get('/login', (req, res) => {
    res.render('users/login');
});

// user login route
router.get('/register', (req, res) => {
    res.render('users/register');
});

// login form post
router.post('/login', (req, res, next) => {
    User.findOne({
        email: req.body.email
    }).exec((err, user) => {
        if (err) {
            res.status(500).send({
                success: false,
                errorMsg: [{ text: err }]
            });
            return;
        }

        if (!user) {
            return res.status(404).send({
                success: false,
                errorMsg: [{ text: 'User Not found.' }]
            });
        }

        var passwordIsValid = bcrypt.compareSync(
            req.body.password,
            user.password
        );
        var token = jwt.sign({ id: user.id }, 'bezkoder-secret-key', {
            expiresIn: 86400 // 24 hours
        });

        if (!passwordIsValid) {
            return res.status(401).send({
                accessToken: null,
                success: false,
                errorMsg: [{ text: 'Invalid Password!' }]
            });
        }
        res.status(200).send({
            success: true,
            userdata: {
                id: user._id,
                username: user.name,
                email: user.email,
                accessToken: token
            }
        });
    });
});

// register form post
router.post('/register', (req, res) => {
    let errors = [];
    if (req.body.password != req.body.confirmPassword) {
        errors.push({ text: 'Passwords do not match!' });
    }
    if (req.body.password.length < 4) {
        errors.push({ text: 'Password must be at least 4 characters' });
    }
    if (errors.length > 0) {
        res.json({ success: false, errorMsg: errors });
    } else {
        User.findOne({
            email: req.body.email
        }).then((user) => {
            if (user) {
                res.json({
                    success: false,
                    errorMsg: [
                        { text: 'A user with the same email already exists' }
                    ]
                });
            } else {
                const newUser = new User({
                    name: req.body.username,
                    email: req.body.email,
                    password: req.body.password
                });
                bcrypt.genSalt(10, (err, salt) => {
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if (err) throw err;
                        newUser.password = hash;
                        newUser
                            .save()
                            .then((user) => {
                                res.json({ success: true, userdata: user });
                            })
                            .catch((err) => {
                                console.log(err);
                                return;
                            });
                    });
                });
            }
        });
    }
});

router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
});

module.exports = router;
