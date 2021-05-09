// jshint esversion:6
require("dotenv").config();
const bodyParser = require("body-parser");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");

//LEVEL 5 Cookies & Sessions
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

//LEVEL 6 OAuth
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

// const encrypt = require("mongoose-encryption"); LEVEL 2
// const md5 = require("md5"); //LEVEL 3 - irreversibly encrypting password

// const bcrypt = require("bcrypt"); //LEVEL 4 - hashing + salting
// const saltRounds = 10;

//Add starting code
const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
	bodyParser.urlencoded({
		extended: true,
	})
);

app.use(
	session({
		secret: "Our little secret.",
		resave: false,
		saveUninitialized: false,
	})
);

app.use(passport.initialize());
app.use(passport.session()); //use passport in sessions

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set("useCreateIndex", true);

//new mongoose.Schema for more complex tasks with plugins
const userSchema = new mongoose.Schema({
	email: String,
	password: String,
	googleId: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//LEVEL 2 Encryption - encrypts passwords when storing in DB
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] }); //only ecrypt password field

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.findById(id, function (err, user) {
		done(err, user);
	});
});

passport.use(
	new GoogleStrategy( //google strategy setup
		{
			clientID: process.env.CLIENT_ID,
			clientSecret: process.env.CLIENT_SECRET,
			callbackURL: "http://localhost:3000/auth/google/secrets",
			userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
		},
		function (accessToken, refreshToken, profile, cb) {
			console.log(profile);
			User.findOrCreate({ googleId: profile.id }, function (err, user) {
				return cb(err, user);
			});
		}
	)
);

//RENDERING PAGES
app.get("/", function (req, res) {
	res.render("home");
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] })); //send to google for authentication

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }), function (req, res) {
	res.redirect("/secrets"); //send back to secrets after google authentication
});

app.get("/login", function (req, res) {
	res.render("login");
});

app.get("/register", function (req, res) {
	res.render("register");
});

app.get("/secrets", function (req, res) {
	if (req.isAuthenticated()) {
		//user is already logged in or authenticated
		res.render("secrets");
	} else {
		res.redirect("/login");
	}
});

app.get("/logout", function (req, res) {
	req.logout();
	res.redirect("/");
});

app.post("/register", function (req, res) {
	User.register({ username: req.body.username }, req.body.password, function (err, user) {
		if (err) {
			console.log(err);
			res.redirect("/register");
		} else {
			passport.authenticate("local")(req, res, function () {
				res.redirect("/secrets");
			});
		}
	});
});

app.post("/login", function (req, res) {
	const user = new User({
		username: req.body.username,
		password: req.body.password,
	});

	req.login(user, function (err) {
		if (err) {
			console.log(err);
		} else {
			passport.authenticate("local")(req, res, function () {
				res.redirect("/secrets");
			});
		}
	});
});

//SERVER START
app.listen(3000, function () {
	console.log("Server started in port 3000");
});

//////////////////////////////////////////////////////////////////////////////
//POST REGISTER
//creating new user from inputs from register page
// bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
// 	const newUser = new User({
// 		email: req.body.username,
// 		password: hash,
// 	});

// 	newUser.save(function (err) {
// 		if (err) {
// 			console.log(err);
// 		} else {
// 			res.render("secrets");
// 		}
// 	});
// });

// POST LOGIN
//LEVEL 1 Authentication - check usernames and passwords against DB values
// const username = req.body.username;
// 	const password = req.body.password;

// 	User.findOne({ email: username }, function (err, foundUser) {
// 		if (err) {
// 			console.log(err);
// 		} else {
// 			if (foundUser) {
// 				bcrypt.compare(password, foundUser.password, function (err, result) {
// 					//check npm bcrypt docs
// 					if (result === true) {
// 						res.render("secrets");
// 					}
// 				});
// 			}
// 		}
// 	});
