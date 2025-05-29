require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jwt-simple");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("MongoDB Connected");
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err); // Log the error
  });

app.use(cors());
app.use(express.json());

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

cloudinary.api.ping((error, result) => {
  if (error) {
    console.error("Cloudinary connection error:", error); // Log the Cloudinary error
  } else {
    console.log("Cloudinary connection successful:", result);
  }
});

// User schema & model
const userSchema = new mongoose.Schema({
  username: String,
  // email: { type: String, unique: true },
  password: String,
});

const User = mongoose.model("User", userSchema);

// Post schema & model
const postSchema = new mongoose.Schema({
  title: String,
  description: String,
  price: String,
  location: String,
  phone: String,
  images: [String],
  category: String, // Add category field
  negotiable: String, // Add negotiable field
  measurement: String, // Add measurement field
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: {
    type: Date,
    default: Date.now, // Automatically set the current date and time
  },
});

const Post = mongoose.model("Post", postSchema);

// Register route
app.post("/api/register", async (req, res) => {
  try {
    console.log("Incoming request body:", req.body); // 👈 Add this
    // const { username, email, password } = req.body;
    const { username, password } = req.body;

    // Check if all required fields are provided
    // if (!username || !email || !password) {
    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "Username, and password are required." });
    }

    // Check if the username already exists in the database
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({
        message: "Username already taken, please choose a different one.",
      });
    }

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user object with hashed password
    const newUser = new User({
      username,
      // email,
      password: hashedPassword,
    });

    // Save the new user to the database
    await newUser.save();

    // Respond with a success message
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.error("Error during sign-up:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Login route
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Look for the user by username (as you are no longer using email)
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // Compare the hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid username or password" });
    }

    // Create a JWT token for the authenticated user
    const payload = { userId: user._id };
    const token = jwt.encode(payload, process.env.JWT_SECRET);

    // Send back the token
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Login failed", error: err.message });
  }
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.decode(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.post(
  "/api/create-post",
  verifyToken,
  upload.array("images", 5), // limit to 5 images
  async (req, res) => {
    const {
      title,
      description,
      price,
      location,
      phone,
      category,
      negotiable,
      measurement,
    } = req.body;

    const images = req.files || [];

    try {
      // Validate required fields
      if (
        !title ||
        !description ||
        !price ||
        !location ||
        !phone ||
        !category ||
        !negotiable
        // (category === "land" && !measurement)
      ) {
        return res.status(400).json({ message: "All fields are required." });
      }

      // const numericPrice = parseFloat(price.replace(/,/g, ""));
      // if (isNaN(numericPrice)) {
      //   return res.status(400).json({ message: "Invalid price format." });
      // }

      const imageUrls = [];

      // Only process image upload if there are images
      if (images.length > 0) {
        const uploadPromises = images.map((image) => {
          return new Promise((resolve, reject) => {
            cloudinary.uploader
              .upload_stream({ resource_type: "image" }, (error, result) => {
                if (error) {
                  reject(error);
                } else {
                  imageUrls.push(result.secure_url);
                  resolve();
                }
              })
              .end(image.buffer);
          });
        });

        await Promise.all(uploadPromises); // Wait for all uploads to finish
      }

      const newPost = new Post({
        title,
        description,
        price, //: //numericPrice,
        location,
        phone,
        category,
        negotiable,
        measurement: category === "land" ? measurement : null,
        images: imageUrls,
        user: req.userId,
        createdAt: new Date(), // Set the creation date when the post is created
      });

      await newPost.save();

      res.status(201).json({
        message: "Post created successfully!",
        post: newPost,
      });
    } catch (err) {
      console.error("Error creating post:", err);
      res
        .status(500)
        .json({ message: "Error creating post", error: err.message });
    }
  }
);

// Get posts route with optional category, keyword, and price filter
app.get("/api/posts", async (req, res) => {
  try {
    const { category, keyword, price, page = 1, limit = 10 } = req.query;

    // Build the filter object
    let filter = {};
    if (category) {
      filter.category = category; // Filter by category if provided
    }

    if (keyword) {
      filter.title = { $regex: keyword, $options: "i" }; // Case-insensitive search for keyword
    }

    // Price filtering (optional)
    if (price) {
      filter.price = { $regex: price }; // Filter posts based on price (regex for flexible matching)
    }

    // Fetch posts with the filter applied and sort by createdAt
    const posts = await Post.find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .populate("user", "username");

    if (!posts || posts.length === 0) {
      return res.status(404).json({ message: "No posts found." });
    }

    res.json(posts); // Send the posts as the response
  } catch (err) {
    console.error("Error fetching posts:", err);
    res
      .status(500)
      .json({ message: "Error fetching posts", error: err.message });
  }
});

// Get posts for a specific user
app.get("/api/posts/user", verifyToken, async (req, res) => {
  try {
    // Fetch posts for the current logged-in user and sort by createdAt in descending order
    const posts = await Post.find({ user: req.userId })
      .sort({ createdAt: -1 }) // Sort by createdAt in descending order (most recent first)
      .populate("user", "username"); // Populate the 'user' field with 'username'

    // Send the posts as the response
    res.json(posts);
  } catch (err) {
    // Handle error in case of failure
    res
      .status(500)
      .json({ message: "Error fetching user posts", error: err.message });
  }
});

// To get user username
app.get("/api/user", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ username: user.username });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Failed to fetch user data", error: err.message });
  }
});

// Delete post route
app.delete("/api/delete-post/:id", verifyToken, async (req, res) => {
  const postId = req.params.id;
  console.log("Delete request received for post:", postId); // Log request

  try {
    // Find the post by ID and ensure it's the user's post
    const post = await Post.findOne({ _id: postId, user: req.userId });

    if (!post) {
      return res
        .status(404)
        .json({ message: "Post not found or not authorized to delete." });
    }

    // Delete images from Cloudinary (if applicable)
    const deleteImagePromises = post.images.map((imageUrl) => {
      const imagePublicId = imageUrl.split("/").pop().split(".")[0];
      return cloudinary.uploader.destroy(imagePublicId);
    });

    // Wait for all image deletions to complete
    await Promise.all(deleteImagePromises);

    // Delete the post from the database
    await Post.deleteOne({ _id: postId });

    res.status(200).json({ message: "Post deleted successfully!" });
  } catch (err) {
    console.error("Error deleting post:", err);
    res
      .status(500)
      .json({ message: "Error deleting post", error: err.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
