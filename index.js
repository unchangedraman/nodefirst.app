import express from "express";
import path from "path";
import mongoose from "mongoose";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

mongoose.connect("mongodb://127.0.0.1:27017/backend", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("Database connected")).catch((e) => console.log(e));

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
});
const User = mongoose.model('User', userSchema);

const app = express();
app.set("view engine", "ejs");
app.use(express.static(path.join(path.resolve(), "public")));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

function verifyToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).send("Unauthorized");
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).send("Forbidden");
    }
    req.user = decoded; // Store user information in the request object
    next();
  });
}

app.get("/", (req, res) => {
  // Check if the user is logged in
  console.log(req.user);
  const username = req.cookies.username;

  if (!username) {
    // User is not logged in, redirect to the login/registration page
    return res.render("index.ejs", { registrationSuccess: false, loggedIn: false });
  }

  // User is logged in, render the welcome page
  res.render("welcome.ejs", { username: username });
});

app.get("/login", (req, res) => {
  // Render the login page
  res.render("login.ejs");
});

app.post("/", async (req, res) => {
  const { name, email, action } = req.body;

  if (action === "register") {
    try {
      const existingUser = await User.findOne({ email: email });
  // Render the login page
      if (existingUser) {
        // User with the provided email already exists
        return res.send("User with this email already exists. Please login.");
      }

      // Create a new user and save it to the database
      await User.create({ name: name, email: email });

      // Render the registration success message on the home page
      return res.render("index.ejs", { registrationSuccess: true, loggedIn: false });
    } catch (error) {
      console.error('Error during registration:', error);
      return res.status(500).send('Internal Server Error');
    }
  } else if (action === "login") {
    // Handle login logic here
    const user = await User.findOne({ email: email });

    if (!user) {
      // User with the provided email doesn't exist
      return res.send("User not found. Please register.");
    }

    if (user.name === name) {
      // Name and email match a user in the database
      const payload = { username: name };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" });

      // Set the JWT token in an HTTP-only cookie
      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
      });

      // Redirect to the welcome page upon successful login
      return res.render("welcome.ejs", { username: name });
    } else {
      // Name doesn't match the user in the database
      return res.send("Invalid name or email. Please try again.");
    }
  } else {
    // Invalid action
    return res.status(400).send('Invalid action');
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie('username');
  res.clearCookie('token'); // Clear the JWT token cookie
  res.redirect("/");
});

// Protected route example
app.get("/protected", verifyToken, (req, res) => {
  // Access req.user to get user information
  res.render("welcome.ejs", { username: req.user.username });
});

app.listen(5000, () => {
  console.log("Server is working");
});
