import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "./src/models/user.js";
import authenticate from "./src/middlewares/authMiddlewares.js";
import checkRole from "./src/middlewares/checkRole.js";

dotenv.config();

const app = express();

// Middleware
app.use(express.json()); // To parse JSON request bodies

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Login Route
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Validate password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.error("Error during login:", error.message);
    res.status(500).json({ error: "Server error during login." });
  }
});

app.get("/api/protected", authenticate, (req, res) => {
  res
    .status(200)
    .json({ message: "Access granted to protected route", user: req.user });
});
//TEST
app.post("/api/test-token", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send("Token missing");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.status(200).json({ message: "Token is valid", decoded });
  } catch (err) {
    res.status(403).json({ message: "Invalid token", error: err.message });
  }
});

// Registration

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    console.log("Received data:", { name, email, password });

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Create new user
    const newUser = new User({
      name,
      email,
      password, // Password will be hashed automatically
    });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error during registration:", error.message);
    res.status(500).json({ error: "Server error during registration." });
  }
});
// role based login admin
app.get("/api/admin", authenticate, checkRole("admin"), (req, res) => {
  res.status(200).json({ message: "Welcome, Admin!" });
});
// role based login User
app.get("/api/user", authenticate, checkRole("user"), (req, res) => {
  res.status(200).json({ message: "Welcome, User!" });
});

// Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
