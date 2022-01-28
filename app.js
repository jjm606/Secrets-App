//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const e = require("express");
// const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const TwitterStrategy = require('passport-twitter-oauth2.0');
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

//Setup the session.
app.use(session({
    secret: 'Our Little Secret.',
    resave: false,
    saveUninitialized: true,
  }));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({email:String,password:String,googleId:String, twitterId:String,linkedinId:String,secret:String});
userSchema.plugin(passportLocalMongoose);
// userSchema.plugin(encrypt,{secret:process.env.SECRET, encryptedFields: ["password"]});
userSchema.plugin(findOrCreate);
const User = mongoose.model("User",userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user);
  });
  
  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
    //   console.log(profile);
    //   console.log(user);
      return cb(err, user);
    });
  }
));

//TWITTER USE
passport.use(
    new TwitterStrategy(
        {
            clientID: process.env.TWITTER_CONSUMER_KEY,
            clientSecret: process.env.TWITTER_CONSUMER_SECRET,
            callbackURL: 'http://localhost:3000/auth/twitter/secrets',
            clientType: "private", // "public" or "private"
            pkce: true, // required,
            state: true, // required
        },
        function (accessToken, refreshToken, profile, done) {
            User.findOrCreate({ twitterId: profile.id }, function (err, user) {
                return done(err, user);
            });
        }
    )
);

passport.use(new LinkedInStrategy({
    clientID: process.env.LINKEDIN_CONSUMER_KEY,
    clientSecret: process.env.LINKEDIN_CONSUMER_SECRET,
    callbackURL: "http://localhost:3000/auth/linkedin/secrets",
    scope: ['r_emailaddress', 'r_liteprofile'],
    state: true
  }, function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ linkedinId: profile.id }, function (err, user) {
        return done(err, user);
    });
    // asynchronous verification, for effect...
    // process.nextTick(function () {
    //   // To keep the example simple, the user's LinkedIn profile is returned to
    //   // represent the logged-in user. In a typical application, you would want
    //   // to associate the LinkedIn account with a user record in your database,
    //   // and return that user instead.
    //   return done(null, profile);
    // });
  }));

app.get("/",function(req,res){
    res.render('home');
});
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get(
    "/auth/twitter",
    passport.authenticate("twitter", { scope: ["offline.access"] })
);

app.get(
    "/auth/twitter/secrets",
    passport.authenticate("twitter", { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect("/");
    }
);

app.get('/auth/linkedin',
  passport.authenticate('linkedin'),
  function(req, res){
    // The request will be redirected to LinkedIn for authentication, so this
    // function will not be called.
  });

app.get('/auth/linkedin/secrets', passport.authenticate('linkedin', {
    successRedirect: '/secrets',
    failureRedirect: '/login'
  }));

app.get("/login",function(req,res){
    res.render("login");
});

app.post("/login",function(req,res){
    // const username = req.body.username;
    // const password = req.body.password;

    // User.findOne({email:username},function(err,userInfo){
    //     if(!err){
    //         if(userInfo!== null){
    //             bcrypt.compare(password,userInfo.password,function(err,result){
    //                 if(result === true){
    //                    res.render('secrets'); 
    //                 }else{
    //                     res.send("Wrong Info");
    //                 }
    //             });
    //             // if(userInfo.password === password){
    //             //     res.render('secrets');
    //             // }else{
    //             //     res.send('Wrong Info');
    //             // }
    //         }else{
    //             res.send("Incorrect username and password");
    //         }
    //     }
    // });

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate('local')(req,res,function(){
                res.redirect('/secrets');
            });
        }
    });
});

app.get("/register",function(req,res){
    res.render("register");
});

app.post("/register",function(req,res){
    
    // const username = req.body.username; 
    // const password = md5(req.body.password);
    // console.log(email);
    // if(username!== undefined){
    //     bcrypt.hash(req.body.password,saltRounds,function(err,hash){
    //         const user = new User({
    //             email: username,
    //             password: hash
    //         });
    //         user.save(function(err){
    //             if(!err){
    //                 // console.log(username);
    //                 console.log('The user was saved in the database');
    //                 res.render('secrets');
    //             }else{
    //                 console.log(err);
    //             }
    //         });
    //     });
    // }else{
    //     console.log('Undefined info was passed');
    // }
    User.register({username: req.body.username, active:false},req.body.password,function(err,user){
        if(err){
            console.log(err);
            res.redirect('/register');
        }else{
            passport.authenticate('local')(req,res,function(){
                res.redirect('/secrets');
            });
        }
    });
});

app.get("/logout",function(req,res){
    req.logout();
    res.redirect("/");
})

app.get("/secrets",function(req,res){
    if(req.isAuthenticated()){
        User.find({secret:{$ne:null}},function(err,foundUsers){
            if(err){
                console.log(err);
            }else{
                if(foundUsers){
                    res.render("secrets",{userSecrets:foundUsers});
                }
            }
        })
    }else{
        res.redirect("/login");
    }
});

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit",function(req,res){
    const secret = req.body.secret;
    User.findById(req.user._id,function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = secret;
                foundUser.save();
                res.redirect("/secrets");
            }else{
                console.log('Havent found the user');
                res.redirect("/secrets");
            }
        }
    });
});

app.listen(3000,function(){
    console.log('Server started at port 3000');
});