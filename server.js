const express = require("express")
const cors = require("cors")
const fs = require("fs")
const path = require("path")
const dotenv = require("dotenv")
const bodyParser = require("body-parser")

// Load environment variables
dotenv.config()

const app = express()
const PORT = process.env.PORT || 3000

// CORS ni to'g'ri sozlash - har qanday frontenddan so'rovlarni qabul qilish uchun
app.use(
  cors({
    origin: "*", // Barcha originlardan so'rovlarni qabul qilish
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
)

app.use(bodyParser.json())
app.use(express.urlencoded({ extended: true }))

// Data papkalarini aniqlash
const dataDir = path.join(__dirname, "data")
const subjectsDir = path.join(dataDir, "subjects")
const resultsPath = path.join(dataDir, "results.json")
const usersPath = path.join(dataDir, "users.json")

// Frontend statik fayllarini o'chirish (chunki frontend alohida deploy qilinadi)
// app.use(express.static(path.join(__dirname, "frontend")))

async function ensureDirectories() {
  try {
    await fs.promises.mkdir(dataDir, { recursive: true })
    await fs.promises.mkdir(subjectsDir, { recursive: true })

    // Create empty results file if it doesn't exist
    try {
      await fs.promises.access(resultsPath)
    } catch (error) {
      await fs.promises.writeFile(resultsPath, JSON.stringify([]))
    }

    // Create users file if it doesn't exist
    try {
      await fs.promises.access(usersPath)
    } catch (error) {
      await fs.promises.writeFile(usersPath, JSON.stringify([]))
    }
  } catch (error) {
    console.error("Error creating directories:", error)
  }
}

// Log requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`)
  next()
})

// API Routes

// Find next available subject ID
app.get("/api/subjects/next-id", (req, res) => {
  try {
    const files = fs.readdirSync(subjectsDir)
    const ids = files
      .filter((file) => file.endsWith(".json"))
      .map((file) => Number.parseInt(file.split("-")[0]))
      .filter((id) => !isNaN(id))

    if (ids.length === 0) {
      return res.json({ nextId: 1 })
    }

    // Find the first gap in the sequence or the next number after the max
    ids.sort((a, b) => a - b)

    for (let i = 1; i <= ids.length; i++) {
      if (i !== ids[i - 1]) {
        return res.json({ nextId: i })
      }
    }

    res.json({ nextId: ids[ids.length - 1] + 1 })
  } catch (error) {
    console.error("Error finding next ID:", error)
    res.status(500).json({ error: "Failed to find next ID" })
  }
})

// Get all subjects
app.get("/api/subjects", (req, res) => {
  try {
    const files = fs.readdirSync(subjectsDir)
    const subjects = []

    for (const file of files) {
      if (file.endsWith(".json")) {
        const data = fs.readFileSync(path.join(subjectsDir, file), "utf8")
        const subject = JSON.parse(data)
        const id = Number.parseInt(file.split("-")[0])
        subjects.push({ id, ...subject })
      }
    }

    // Sort subjects by ID
    subjects.sort((a, b) => a.id - b.id)

    res.json(subjects)
  } catch (error) {
    console.error("Error getting subjects:", error)
    res.status(500).json({ error: "Failed to get subjects" })
  }
})

// Get a specific subject
app.get("/api/subjects/:id", (req, res) => {
  try {
    const id = req.params.id
    const filePath = path.join(subjectsDir, `${id}-fan.json`)

    try {
      const data = fs.readFileSync(filePath, "utf8")
      const subject = JSON.parse(data)
      res.json({ id: Number.parseInt(id), ...subject })
    } catch (error) {
      if (error.code === "ENOENT") {
        res.status(404).json({ error: "Subject not found" })
      } else {
        throw error
      }
    }
  } catch (error) {
    console.error("Error getting subject:", error)
    res.status(500).json({ error: "Failed to get subject" })
  }
})

// Create or update a subject
app.post("/api/subjects/:id", (req, res) => {
  try {
    const id = req.params.id
    const subject = req.body

    // Remove id from subject if it exists
    const { id: subjectId, ...subjectData } = subject

    const filePath = path.join(subjectsDir, `${id}-fan.json`)
    fs.writeFileSync(filePath, JSON.stringify(subjectData, null, 2))

    res.json({ message: "Subject saved successfully", id })
  } catch (error) {
    console.error("Error saving subject:", error)
    res.status(500).json({ error: "Failed to save subject" })
  }
})

// Delete a subject
app.delete("/api/subjects/:id", (req, res) => {
  try {
    const id = req.params.id
    const filePath = path.join(subjectsDir, `${id}-fan.json`)

    try {
      fs.unlinkSync(filePath)
      res.json({ message: "Subject deleted successfully" })
    } catch (error) {
      if (error.code === "ENOENT") {
        res.status(404).json({ error: "Subject not found" })
      } else {
        throw error
      }
    }
  } catch (error) {
    console.error("Error deleting subject:", error)
    res.status(500).json({ error: "Failed to delete subject" })
  }
})

// Get all results
app.get("/api/results", (req, res) => {
  try {
    const data = fs.readFileSync(resultsPath, "utf8")
    const results = JSON.parse(data)
    res.json(results)
  } catch (error) {
    console.error("Error getting results:", error)
    res.status(500).json({ error: "Failed to get results" })
  }
})

// Get results for a specific user
app.get("/api/results/user/:username", (req, res) => {
  try {
    const username = req.params.username
    const data = fs.readFileSync(resultsPath, "utf8")
    const results = JSON.parse(data)

    const userResults = results.filter((result) => result.studentName === username)
    res.json(userResults)
  } catch (error) {
    console.error("Error getting user results:", error)
    res.status(500).json({ error: "Failed to get user results" })
  }
})

// Add a new result
app.post("/api/results", (req, res) => {
  try {
    const newResult = req.body

    // Add id and date if not provided
    if (!newResult.id) {
      newResult.id = Date.now()
    }
    if (!newResult.date) {
      newResult.date = new Date().toISOString()
    }

    const data = fs.readFileSync(resultsPath, "utf8")
    const results = JSON.parse(data)

    results.push(newResult)

    fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2))

    res.json({ message: "Result added successfully", result: newResult })
  } catch (error) {
    console.error("Error adding result:", error)
    res.status(500).json({ error: "Failed to add result" })
  }
})

// User authentication
app.post("/api/auth/login", (req, res) => {
  try {
    console.log("Login request body:", req.body)
    const { username, password } = req.body

    const data = fs.readFileSync(usersPath, "utf8")
    const users = JSON.parse(data)

    const user = users.find((u) => u.username === username && u.password === password)

    if (user) {
      // Don't send password back to client
      const { password, ...userWithoutPassword } = user
      res.json({ success: true, user: userWithoutPassword })
    } else {
      res.status(401).json({ success: false, message: "Invalid username or password" })
    }
  } catch (error) {
    console.error("Error during login:", error)
    res.status(500).json({ error: "Login failed" })
  }
})

// Register a new user
app.post("/api/auth/register", (req, res) => {
  try {
    console.log("Register request body:", req.body)
    const { username, password, fullName } = req.body

    const data = fs.readFileSync(usersPath, "utf8")
    const users = JSON.parse(data)

    // Check if username already exists
    if (users.some((u) => u.username === username)) {
      return res.status(400).json({ success: false, message: "Username already exists" })
    }

    const newUser = {
      id: Date.now(),
      username,
      password,
      fullName,
      isAdmin: false,
    }

    users.push(newUser)

    fs.writeFileSync(usersPath, JSON.stringify(users, null, 2))

    // Don't send password back to client
    const { password: pwd, ...userWithoutPassword } = newUser
    res.json({ success: true, user: userWithoutPassword })
  } catch (error) {
    console.error("Error during registration:", error)
    res.status(500).json({ error: "Registration failed" })
  }
})

// Add this before the "Serve index.html for all other routes" section
app.get("/db/:file", (req, res, next) => {
  const fileName = req.params.file
  const match = fileName.match(/^(\d+)-fan\.json$/)

  if (match) {
    const subjectId = match[1]
    const filePath = path.join(subjectsDir, `${subjectId}-fan.json`)

    try {
      if (fs.existsSync(filePath)) {
        const data = fs.readFileSync(filePath, "utf8")
        return res.type("application/json").send(data)
      } else {
        return res.status(404).json({ error: "Subject not found" })
      }
    } catch (error) {
      console.error(`Error serving subject ${subjectId}:`, error)
      return res.status(500).json({ error: "Failed to get subject" })
    }
  }

  // If not a subject file, continue to the next route handler
  next()
})

// Frontend uchun yo'naltirishlarni o'chirish (chunki frontend alohida deploy qilinadi)
// app.get("*", (req, res) => {
//   res.sendFile(path.join(__dirname, "frontend", "index.html"))
// })

// Initialize admin user if no users exist
async function initializeAdmin() {
  try {
    const data = await fs.promises.readFile(usersPath, "utf8")
    const users = JSON.parse(data)

    if (users.length === 0) {
      const adminUser = {
        id: 1,
        username: "admin",
        password: "admin123",
        fullName: "Administrator",
        isAdmin: true,
      }

      users.push(adminUser)
      await fs.promises.writeFile(usersPath, JSON.stringify(users, null, 2))
      console.log("Admin user created")
    }
  } catch (error) {
    console.error("Error initializing admin:", error)
  }
}

// Start the server
async function startServer() {
  await ensureDirectories()
  await initializeAdmin()

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
    console.log(`API is available at http://localhost:${PORT}/api`)
  })
}

startServer()
