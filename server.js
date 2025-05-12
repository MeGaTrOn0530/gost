const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const jwt = require("jsonwebtoken");

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || "your-secret-key";

// CORS sozlamalari - frontend uchun
app.use(
  cors({
    origin: [
      "https://papaya-concha-4b8dbf.netlify.app",
      "https://68224b77e1ae317febbcef73--papaya-concha-4b8dbf.netlify.app", 
      "https://gost2025.netlify.app",  // Yangi URL qo'shildi
      "http://localhost:3000"
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true, // Cookie yuborish uchun muhim
  })
);

app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session sozlamalari
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", // HTTPS uchun
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 kun
      sameSite: "none" // Domenlar aro cookie ishlashi uchun
    },
  })
);

// Data papkalarini aniqlash
const dataDir = path.join(__dirname, "data");
const subjectsDir = path.join(dataDir, "subjects");
const resultsPath = path.join(dataDir, "results.json");
const usersPath = path.join(dataDir, "users.json");
const testsDir = path.join(dataDir, "tests");

async function ensureDirectories() {
  try {
    await fs.promises.mkdir(dataDir, { recursive: true });
    await fs.promises.mkdir(subjectsDir, { recursive: true });
    await fs.promises.mkdir(testsDir, { recursive: true });

    // Create empty results file if it doesn't exist
    try {
      await fs.promises.access(resultsPath);
    } catch (error) {
      await fs.promises.writeFile(resultsPath, JSON.stringify([]));
    }

    // Create users file if it doesn't exist
    try {
      await fs.promises.access(usersPath);
    } catch (error) {
      await fs.promises.writeFile(usersPath, JSON.stringify([]));
    }
  } catch (error) {
    console.error("Error creating directories:", error);
  }
}

// Log requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// Token tekshirish middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    // Token yo'q, lekin session bo'lishi mumkin
    if (req.session.user) {
      return next();
    }
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
  if (req.session.user || req.user) {
    next();
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
};

// Middleware to check if user is admin
const isAdmin = (req, res, next) => {
  if ((req.session.user && req.session.user.isAdmin) || 
      (req.user && req.user.isAdmin)) {
    next();
  } else {
    res.status(403).json({ error: "Forbidden" });
  }
};

// API Routes

// Check session
app.get("/api/auth/check-session", isAuthenticated, (req, res) => {
  res.json(req.session.user || req.user);
});

// Check admin session
app.get("/api/auth/check-admin", isAdmin, (req, res) => {
  res.json(req.session.user || req.user);
});

// Login
app.post("/api/auth/login", (req, res) => {
  try {
    console.log("Login request body:", req.body);
    const { username, password } = req.body;

    const data = fs.readFileSync(usersPath, "utf8");
    const users = JSON.parse(data);

    const user = users.find((u) => u.username === username && u.password === password);

    if (user) {
      // Don't send password back to client
      const { password, ...userWithoutPassword } = user;

      // Create token
      const token = jwt.sign(
        { id: user.id, username: user.username, isAdmin: user.isAdmin, fullName: user.fullName },
        SECRET_KEY,
        { expiresIn: '24h' }
      );

      // Save user to session
      req.session.user = userWithoutPassword;

      res.json({ 
        success: true, 
        user: userWithoutPassword,
        token: token
      });
    } else {
      res.status(401).json({ success: false, message: "Invalid username or password" });
    }
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).json({ error: "Logout failed" });
    }
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});

// Register
app.post("/api/auth/register", (req, res) => {
  try {
    console.log("Register request body:", req.body);
    const { username, password, fullName } = req.body;

    const data = fs.readFileSync(usersPath, "utf8");
    const users = JSON.parse(data);

    // Check if username already exists
    if (users.some((u) => u.username === username)) {
      return res.status(400).json({ success: false, message: "Username already exists" });
    }

    const newUser = {
      id: Date.now(),
      username,
      password,
      fullName,
      isAdmin: false,
    };

    users.push(newUser);

    fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));

    // Don't send password back to client
    const { password: pwd, ...userWithoutPassword } = newUser;

    // Create token
    const token = jwt.sign(
      { id: newUser.id, username: newUser.username, isAdmin: newUser.isAdmin, fullName: newUser.fullName },
      SECRET_KEY,
      { expiresIn: '24h' }
    );

    // Save user to session
    req.session.user = userWithoutPassword;

    res.json({ 
      success: true, 
      user: userWithoutPassword,
      token: token
    });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Find next available subject ID
app.get("/api/subjects/next-id", verifyToken, isAdmin, (req, res) => {
  try {
    const files = fs.readdirSync(subjectsDir);
    const ids = files
      .filter((file) => file.endsWith(".json"))
      .map((file) => Number.parseInt(file.split("-")[0]))
      .filter((id) => !isNaN(id));

    if (ids.length === 0) {
      return res.json({ nextId: 1 });
    }

    // Find the first gap in the sequence or the next number after the max
    ids.sort((a, b) => a - b);

    for (let i = 1; i <= ids.length; i++) {
      if (i !== ids[i - 1]) {
        return res.json({ nextId: i });
      }
    }

    res.json({ nextId: ids[ids.length - 1] + 1 });
  } catch (error) {
    console.error("Error finding next ID:", error);
    res.status(500).json({ error: "Failed to find next ID" });
  }
});

// Get all subjects
app.get("/api/subjects", verifyToken, isAuthenticated, (req, res) => {
  try {
    const files = fs.readdirSync(subjectsDir);
    const subjects = [];

    for (const file of files) {
      if (file.endsWith(".json")) {
        const data = fs.readFileSync(path.join(subjectsDir, file), "utf8");
        const subject = JSON.parse(data);
        const id = Number.parseInt(file.split("-")[0]);
        subjects.push({ id, ...subject });
      }
    }

    // Sort subjects by ID
    subjects.sort((a, b) => a.id - b.id);

    res.json(subjects);
  } catch (error) {
    console.error("Error getting subjects:", error);
    res.status(500).json({ error: "Failed to get subjects" });
  }
});

// Get a specific subject
app.get("/api/subjects/:id", verifyToken, isAuthenticated, (req, res) => {
  try {
    const id = req.params.id;
    const filePath = path.join(subjectsDir, `${id}-fan.json`);

    try {
      const data = fs.readFileSync(filePath, "utf8");
      const subject = JSON.parse(data);
      res.json({ id: Number.parseInt(id), ...subject });
    } catch (error) {
      if (error.code === "ENOENT") {
        res.status(404).json({ error: "Subject not found" });
      } else {
        throw error;
      }
    }
  } catch (error) {
    console.error("Error getting subject:", error);
    res.status(500).json({ error: "Failed to get subject" });
  }
});

// Select a subject for testing
app.post("/api/subjects/select/:id", verifyToken, isAuthenticated, (req, res) => {
  try {
    const id = req.params.id;
    const { subjectData } = req.body;

    // Save selected subject to session
    req.session.selectedSubject = {
      id: Number(id),
      data: subjectData,
    };

    res.json({ success: true });
  } catch (error) {
    console.error("Error selecting subject:", error);
    res.status(500).json({ error: "Failed to select subject" });
  }
});

// Get selected subject
app.get("/api/subjects/selected", verifyToken, isAuthenticated, (req, res) => {
  if (!req.session.selectedSubject) {
    return res.status(404).json({ error: "No subject selected" });
  }

  res.json(req.session.selectedSubject);
});

// Create or update a subject
app.post("/api/subjects/:id", verifyToken, isAdmin, (req, res) => {
  try {
    const id = req.params.id;
    const subject = req.body;

    // Remove id from subject if it exists
    const { id: subjectId, ...subjectData } = subject;

    const filePath = path.join(subjectsDir, `${id}-fan.json`);
    fs.writeFileSync(filePath, JSON.stringify(subjectData, null, 2));

    res.json({ message: "Subject saved successfully", id });
  } catch (error) {
    console.error("Error saving subject:", error);
    res.status(500).json({ error: "Failed to save subject" });
  }
});

// Delete a subject
app.delete("/api/subjects/:id", verifyToken, isAdmin, (req, res) => {
  try {
    const id = req.params.id;
    const filePath = path.join(subjectsDir, `${id}-fan.json`);

    try {
      fs.unlinkSync(filePath);
      res.json({ message: "Subject deleted successfully" });
    } catch (error) {
      if (error.code === "ENOENT") {
        res.status(404).json({ error: "Subject not found" });
      } else {
        throw error;
      }
    }
  } catch (error) {
    console.error("Error deleting subject:", error);
    res.status(500).json({ error: "Failed to delete subject" });
  }
});

// Save test state
app.post("/api/tests/save-state", verifyToken, isAuthenticated, (req, res) => {
  try {
    const userId = req.session.user?.id || req.user?.id;
    const testData = req.body;

    const filePath = path.join(testsDir, `${userId}-test.json`);
    fs.writeFileSync(filePath, JSON.stringify(testData, null, 2));

    res.json({ success: true });
  } catch (error) {
    console.error("Error saving test state:", error);
    res.status(500).json({ error: "Failed to save test state" });
  }
});

// Save test answer
app.post("/api/tests/save-answer", verifyToken, isAuthenticated, (req, res) => {
  try {
    const userId = req.session.user?.id || req.user?.id;
    const { questionIndex, answer } = req.body;

    const filePath = path.join(testsDir, `${userId}-test.json`);

    // Read current test data
    const testData = JSON.parse(fs.readFileSync(filePath, "utf8"));

    // Update answer
    testData.userAnswers[questionIndex] = answer;

    // Save updated test data
    fs.writeFileSync(filePath, JSON.stringify(testData, null, 2));

    res.json({ success: true });
  } catch (error) {
    console.error("Error saving answer:", error);
    res.status(500).json({ error: "Failed to save answer" });
  }
});

// Save timer state
app.post("/api/tests/save-timer", verifyToken, isAuthenticated, (req, res) => {
  try {
    const userId = req.session.user?.id || req.user?.id;
    const { timeLeft } = req.body;

    const filePath = path.join(testsDir, `${userId}-test.json`);

    // Read current test data
    const testData = JSON.parse(fs.readFileSync(filePath, "utf8"));

    // Update timer
    testData.timeLeft = timeLeft;

    // Save updated test data
    fs.writeFileSync(filePath, JSON.stringify(testData, null, 2));

    res.json({ success: true });
  } catch (error) {
    console.error("Error saving timer state:", error);
    res.status(500).json({ error: "Failed to save timer state" });
  }
});

// Clear test state
app.post("/api/tests/clear-state", verifyToken, isAuthenticated, (req, res) => {
  try {
    const userId = req.session.user?.id || req.user?.id;
    const filePath = path.join(testsDir, `${userId}-test.json`);

    // Delete test data file if exists
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Clear selected subject from session
    delete req.session.selectedSubject;

    res.json({ success: true });
  } catch (error) {
    console.error("Error clearing test state:", error);
    res.status(500).json({ error: "Failed to clear test state" });
  }
});

// Get all results
app.get("/api/results", verifyToken, isAuthenticated, (req, res) => {
  try {
    const data = fs.readFileSync(resultsPath, "utf8");
    const results = JSON.parse(data);

    // If user is not admin, only return their results
    const isAdmin = req.session.user?.isAdmin || req.user?.isAdmin;
    const fullName = req.session.user?.fullName || req.user?.fullName;
    
    if (!isAdmin) {
      const userResults = results.filter((result) => result.studentName === fullName);
      return res.json(userResults);
    }

    res.json(results);
  } catch (error) {
    console.error("Error getting results:", error);
    res.status(500).json({ error: "Failed to get results" });
  }
});

// Get results for current user
app.get("/api/results/user", verifyToken, isAuthenticated, (req, res) => {
  try {
    const data = fs.readFileSync(resultsPath, "utf8");
    const results = JSON.parse(data);
    const fullName = req.session.user?.fullName || req.user?.fullName;

    const userResults = results.filter((result) => result.studentName === fullName);
    res.json(userResults);
  } catch (error) {
    console.error("Error getting user results:", error);
    res.status(500).json({ error: "Failed to get user results" });
  }
});

// Add a new result
app.post("/api/results", verifyToken, isAuthenticated, (req, res) => {
  try {
    const newResult = req.body;
    const fullName = req.session.user?.fullName || req.user?.fullName;

    // Add id, studentName and date if not provided
    if (!newResult.id) {
      newResult.id = Date.now();
    }
    if (!newResult.studentName) {
      newResult.studentName = fullName;
    }
    if (!newResult.date) {
      newResult.date = new Date().toISOString();
    }

    const data = fs.readFileSync(resultsPath, "utf8");
    const results = JSON.parse(data);

    results.push(newResult);

    fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));

    res.json({ message: "Result added successfully", result: newResult });
  } catch (error) {
    console.error("Error adding result:", error);
    res.status(500).json({ error: "Failed to add result" });
  }
});

// Add this before the "Serve index.html for all other routes" section
app.get("/db/:file", (req, res, next) => {
  const fileName = req.params.file;
  const match = fileName.match(/^(\d+)-fan\.json$/);

  if (match) {
    const subjectId = match[1];
    const filePath = path.join(subjectsDir, `${subjectId}-fan.json`);

    try {
      if (fs.existsSync(filePath)) {
        const data = fs.readFileSync(filePath, "utf8");
        return res.type("application/json").send(data);
      } else {
        return res.status(404).json({ error: "Subject not found" });
      }
    } catch (error) {
      console.error(`Error serving subject ${subjectId}:`, error);
      return res.status(500).json({ error: "Failed to get subject" });
    }
  }

  // If not a subject file, continue to the next route handler
  next();
});

// Initialize admin user if no users exist
async function initializeAdmin() {
  try {
    const data = await fs.promises.readFile(usersPath, "utf8");
    const users = JSON.parse(data);

    if (users.length === 0) {
      const adminUser = {
        id: 1,
        username: "admin",
        password: "admin123",
        fullName: "Administrator",
        isAdmin: true,
      };

      users.push(adminUser);
      await fs.promises.writeFile(usersPath, JSON.stringify(users, null, 2));
      console.log("Admin user created");
    }
  } catch (error) {
    console.error("Error initializing admin:", error);
  }
}

// Start the server
async function startServer() {
  await ensureDirectories();
  await initializeAdmin();

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`API is available at http://localhost:${PORT}/api`);
  });
}

startServer();