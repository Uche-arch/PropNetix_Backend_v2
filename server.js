require("dotenv").config();
const cron = require("node-cron");
const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const cors = require("cors");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const admin = require("firebase-admin");
// const serviceAccount = require("./serviceAccountKey.json");

const app = express();
const PORT = process.env.PORT || 5000;

// Firebase Admin Setup
// admin.initializeApp({
//   credential: admin.credential.cert(serviceAccount),
// });

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  }),
});

app.use(express.json());

// Middleware
app.use(cors());
app.use(express.json());

console.log("User:", process.env.GMAIL_USER);
console.log("Pass:", process.env.GMAIL_PASS);

// ✅ Setup Nodemailer (using Gmail)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER, // your Gmail
    pass: process.env.GMAIL_PASS, // app password from Google
  },
});

// ✅ Route: Send Custom Verification Email
app.post("/api/send-verification-email", async (req, res) => {
  const { uid, email } = req.body;

  if (!uid || !email) {
    return res.status(400).json({ message: "Missing uid or email" });
  }

  const verificationLink = `https://propnetix-backend-v2.onrender.com/api/verify-email?uid=${uid}`;

  const mailOptions = {
    from: `"PropNetix Support" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: "Verify Your Email - PropNetix",
    html: `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #ffffff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
    <div style="text-align: center; margin-bottom: 18px;">
      <h2 style="color: #111; margin: 0;">Welcome to PropNetix</h2>
    </div>
    <p style="font-size: 16px; color: #333;">Hi there,</p>
    <p style="font-size: 16px; color: #333;">
      Thank you for signing up for PropNetix! You're just one step away from unlocking your account and accessing property listings tailored for you.
    </p>
    <p style="font-size: 16px; color: #333;"> Please click the button below to verify your email address. Once verified, you’ll be redirected to the login page.</p>
    <div style="text-align: center; margin: 25px 0;">
      <a href="${verificationLink}" style="background-color: #272727; color: white; padding: 12px 20px; border-radius: 6px; text-decoration: none; font-weight: bold; display: inline-block; font-size: 14px;">
        Verify My Email
      </a>
    </div>
    <p style="font-size: 14px; color: #555; text-align: center; margin-bottom: 20px;">
     If this email landed in your spam folder, please mark it as “Not Spam” so you don’t miss future updates.
  </p>
    <p style="font-size: 14px; color: #666; text-align: center;">
      If you didn’t sign up for PropNetix, you can safely ignore this email.
    </p>
    <hr style="margin: 2px 0; border: none; border-top: 1px solid #eee;" />
    <p style="font-size: 13px; color: #999; text-align: center; margin: 5px 0 0 0;">
      &copy; ${new Date().getFullYear()} PropNetix. All rights reserved.
    </p>
  </div>
  </div>
  `,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ message: "Verification email sent" });
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).json({ message: "Failed to send email" });
  }
});

// ✅ Route: Handle Email Click (verifies user)
app.get("/api/verify-email", async (req, res) => {
  const uid = req.query.uid;

  if (!uid) {
    return res.status(400).send("Missing UID");
  }

  try {
    await admin.auth().updateUser(uid, { emailVerified: true });
    // 🔁 Redirect user to login page on frontend
    return res.redirect("https://propnetix.netlify.app/login.html");
  } catch (error) {
    console.error("Email verification error:", error);
    return res.status(500).send("Error verifying email.");
  }
});

// MIDDLEWARE WITH SOME DEBUGGIN
const verifyFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.status(401).json({ message: "Missing token" });

  const token = authHeader.replace("Bearer ", "");
  console.log("Received token:", token.slice(0, 10) + "...");

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    console.log("Decoded UID:", decodedToken.uid);
    req.firebaseUid = decodedToken.uid;
    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);
    return res
      .status(403)
      .json({ message: "Invalid Firebase token", error: error.message });
  }
};

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  uid: { type: String, required: true, unique: true }, // Firebase UID
  username: { type: String, required: true, unique: true },
});
const User = mongoose.model("User", userSchema);

const postSchema = new mongoose.Schema({
  title: String,
  description: String,
  price: String,
  location: String,
  phone: String,
  images: [String],
  category: String,
  negotiable: String,
  measurement: String,
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
});
const Post = mongoose.model("Post", postSchema);

// Register route — create MongoDB user after Firebase signup
app.post("/api/register", verifyFirebaseToken, async (req, res) => {
  const { username } = req.body;

  if (!username)
    return res.status(400).json({ message: "Username is required" });

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser)
      return res.status(400).json({ message: "Username already taken" });

    const newUser = new User({ uid: req.firebaseUid, username });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error registering user", error: err.message });
  }
});

// GET /api/check-username?username=someusername
app.get("/api/check-username", async (req, res) => {
  const username = req.query.username?.trim();

  if (!username) {
    return res
      .status(400)
      .json({ message: "Username query parameter is required" });
  }

  try {
    const existingUser = await User.findOne({ username });

    if (existingUser) {
      return res.json({
        available: false,
        message: "Username is already taken",
      });
    } else {
      return res.json({ available: true, message: "Username is available" });
    }
  } catch (err) {
    console.error("Error checking username:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// Get current user profile
app.get("/api/user", verifyFirebaseToken, async (req, res) => {
  try {
    const user = await User.findOne({ uid: req.firebaseUid });
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ username: user.username });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error fetching user", error: err.message });
  }
});

// Create a post
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.post(
  "/api/create-post",
  verifyFirebaseToken,
  upload.array("images", 5),
  async (req, res) => {
    try {
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

      const user = await User.findOne({ uid: req.firebaseUid });
      if (!user) return res.status(404).json({ message: "User not found" });

      const imageUrls = [];

      if (req.files.length > 0) {
        const uploadPromises = req.files.map((image) => {
          return new Promise((resolve, reject) => {
            cloudinary.uploader
              .upload_stream({ resource_type: "image" }, (error, result) => {
                if (error) reject(error);
                else {
                  imageUrls.push(result.secure_url);
                  resolve();
                }
              })
              .end(image.buffer);
          });
        });
        await Promise.all(uploadPromises);
      }

      const newPost = new Post({
        title,
        description,
        price,
        location,
        phone,
        category,
        negotiable,
        measurement: category === "land" ? measurement : null,
        images: imageUrls,
        user: user._id,
      });

      await newPost.save();
      res.status(201).json({ message: "Post created", post: newPost });
    } catch (err) {
      res
        .status(500)
        .json({ message: "Post creation failed", error: err.message });
    }
  }
);

// Get posts
app.get("/api/posts", async (req, res) => {
  const { category, keyword, price, page = 1, limit = 10 } = req.query;

  const filter = {};
  if (category) filter.category = category;
  if (keyword) filter.title = { $regex: keyword, $options: "i" };
  if (price) filter.price = { $regex: price };

  try {
    const posts = await Post.find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .populate("user", "username");

    res.json(posts);
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error fetching posts", error: err.message });
  }
});

// Get posts for current user
app.get("/api/posts/user", verifyFirebaseToken, async (req, res) => {
  try {
    const user = await User.findOne({ uid: req.firebaseUid });
    if (!user) return res.status(404).json({ message: "User not found" });

    const posts = await Post.find({ user: user._id }).sort({ createdAt: -1 });
    res.json(posts);
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error fetching user posts", error: err.message });
  }
});

// Delete a post
app.delete("/api/delete-post/:id", verifyFirebaseToken, async (req, res) => {
  try {
    const user = await User.findOne({ uid: req.firebaseUid });
    if (!user) return res.status(404).json({ message: "User not found" });

    const post = await Post.findOne({ _id: req.params.id, user: user._id });
    if (!post)
      return res.status(404).json({ message: "Post not found or not yours" });

    const deleteImagePromises = post.images.map((imageUrl) => {
      const publicId = imageUrl.split("/").pop().split(".")[0];
      return cloudinary.uploader.destroy(publicId);
    });

    await Promise.all(deleteImagePromises);
    await Post.deleteOne({ _id: req.params.id });

    res.json({ message: "Post deleted" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error deleting post", error: err.message });
  }
});

// Get total number of posts (all categories)
app.get("/api/posts-total", async (req, res) => {
  try {
    const count = await Post.countDocuments();
    res.json({ count });
  } catch (err) {
    res.status(500).json({ error: "Failed to get total posts count" });
  }
});

// Get number of posts for a specific category
app.get("/api/posts-count/:category", async (req, res) => {
  try {
    const { category } = req.params;
    const count = await Post.countDocuments({ category });
    res.json({ count });
  } catch (err) {
    res.status(500).json({ error: "Failed to get category posts count" });
  }
});

      // Added this block above latest 2 blocks


// 🧹 CRON JOB: Daily cleanup of unverified Firebase users older than 24h
cron.schedule("0 0 * * *", async () => {
  try {
    console.log("Running daily cleanup for unverified Firebase users...");

    const oneDayAgo = Date.now() - 48 * 60 * 60 * 1000;
    const listAllUsers = async (nextPageToken) => {
      const result = await admin.auth().listUsers(1000, nextPageToken);
      const deletions = [];

      result.users.forEach((user) => {
        const createdAt = new Date(user.metadata.creationTime).getTime();
        const isUnverifiedOld = !user.emailVerified && createdAt < oneDayAgo;

        if (isUnverifiedOld) {
          deletions.push(admin.auth().deleteUser(user.uid));
          console.log(`Scheduled deletion for user: ${user.email}`);
        }
      });

      await Promise.all(deletions);

      if (result.pageToken) {
        await listAllUsers(result.pageToken);
      }
    };

    await listAllUsers();
    console.log("✅ Unverified user cleanup completed.");
  } catch (error) {
    console.error("❌ Error cleaning unverified users:", error.message);
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log("Email:", process.env.GMAIL_USER);
  console.log("Pass:", process.env.GMAIL_PASS ? "Loaded" : "Missing");
});

// New comment to push code to new github repo
