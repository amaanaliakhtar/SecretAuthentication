// jshint esversion:6
const bodyParser = require("body-parser");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

//Add starting code
const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
	bodyParser.urlencoded({
		extended: true,
	})
);

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true });

//new mongoose.Schema for more complex tasks
const userSchema = new mongoose.Schema({
	email: String,
	password: String,
});

//LEVEL 2 Encryption - encrypts passwords when storing in DB
const secret = "Thisisourlittlesecret.";
userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] }); //only ecrypt password field

const User = new mongoose.model("User", userSchema);

//RENDERING PAGES
app.get("/", function (req, res) {
	res.render("home");
});

app.get("/login", function (req, res) {
	res.render("login");
});

app.get("/register", function (req, res) {
	res.render("register");
});

app.post("/register", function (req, res) {
	//creating new user from inputs from register page
	const newUser = new User({
		email: req.body.username,
		password: req.body.password,
	});

	newUser.save(function (err) {
		if (err) {
			console.log(err);
		} else {
			res.render("secrets");
		}
	});
});

//LEVEL 1 Authentication - check usernames and passwords against DB values
app.post("/login", function (req, res) {
	const username = req.body.username;
	const password = req.body.password;

	User.findOne({ email: username }, function (err, foundUser) {
		if (err) {
			console.log(err);
		} else {
			if (foundUser) {
				if (foundUser.password === password) {
					res.render("secrets");
				}
			}
		}
	});
});

//SEVER START
app.listen(3000, function () {
	console.log("Server started in port 3000");
});
