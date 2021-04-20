const express = require("express");
const app = express();
const morgan = require("morgan");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");

const userRoutes = require("./api/routes/user");

mongoose.connect(
	"mongodb+srv://ilad:" +
		process.env.MONGO_ATLAS_PW +
		"@todo-app.tnrgb.mongodb.net/todo-app?retryWrites=true&w=majority",
	{
		useNewUrlParser: true,
		useUnifiedTopology: true,
	}
);

mongoose.Promise = global.Promise;

app.use(morgan("dev"));
app.use("/uploads", express.static("uploads"));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use((req, res, next) => {
	res.setHeader("Access-Control-Allow-Origin", "*");
	res.setHeader(
		"Access-Control-Allow-Headers",
		"Origin,Cache-Control,Accept,X-Access-Token ,X-Requested-With, Content-Type, Access-Control-Request-Method"
	);
	if (req.method === "OPTIONS") {
		res.setHeader(
			"Access-Control-Allow-Methods",
			"GET,HEAD,OPTIONS,PATCH,POST,PUT,DELETE"
		);
		return res.status(200).json({});
	}
	next();
});

app.use("/user", userRoutes);

app.use((req, res, next) => {
	const error = new Error("Not found");
	error.status = 404;
	next(error);
});

app.use((error, req, res, next) => {
	res.status(error.status || 500);
	res.json({
		error: {
			message: error.message,
		},
	});
});

module.exports = app;
