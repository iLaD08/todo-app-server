const express = require("express");
const router = express.Router();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("../models/user");

const checkAuth = require("../middleware/check-auth.js");

router.get("/:user", checkAuth, (req, res, next) => {
	User.find({ username: req.params.user })
		.select("_id username email todos")
		.exec()
		.then((doc) => res.status(200).json(doc[0]))
		.catch((err) => res.status(500).json({ err }));
});

router.post("/signup", (req, res, next) => {
	User.find({ email: req.body.email })
		.exec()
		.then((user) => {
			if (user.length >= 1) {
				return res.status(409).json({
					message: "Mail exists",
				});
			} else {
				bcrypt.hash(req.body.password, 10, (err, hash) => {
					if (err) {
						return res.status(500).json({
							error: err,
						});
					} else {
						const user = new User({
							_id: new mongoose.Types.ObjectId(),
							username: req.body.username,
							email: req.body.email,
							password: hash,
							todo: [],
						});
						user
							.save()
							.then((result) => {
								res.status(201).json({
									message: "User created",
								});
							})
							.catch((err) => {
								res.status(500).json({
									error: err,
								});
							});
					}
				});
			}
		});
});

router.post("/signin", (req, res, next) => {
	User.find({ username: req.body.username })
		.exec()
		.then((user) => {
			if (user.length < 1) {
				return res.status(401).json({
					message: "Auth failed",
				});
			}
			bcrypt.compare(req.body.password, user[0].password, (err, result) => {
				if (err) {
					return res.status(401).json({
						message: "Auth failed",
					});
				}
				if (result) {
					const token = jwt.sign(
						{
							userId: user[0]._id,
							username: user[0].username,
							email: user[0].email,
						},
						process.env.PRIVATE_KEY,
						{
							expiresIn: "1h",
						}
					);
					return res.status(200).json({
						message: "Auth successful",
						token: token,
					});
				}
				res.status(401).json({
					message: "Auth failed",
				});
			});
		})
		.catch((err) => {
			res.status(500).json({
				error: err,
			});
		});
});

router.delete("/:userId", checkAuth, (req, res, next) => {
	User.remove({ _id: req.params.userId })
		.exec()
		.then((result) => res.status(200).json({ message: "User deleted" }))
		.catch((err) => res.status(500).json({ error: err }));
});

module.exports = router;
