import cors from 'cors';
import express from "express";
import mongoose from "mongoose";
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

import User from "./models/users.js";
import Event from "./models/events.js";

const app = express();
app.use(cors({
    origin: ['http://localhost:3000','https://eveosmania.vercel.app'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true 
}));
app.use(express.json());

const mongoose_url = "mongodb+srv://dasisaisrivathsav20042:Lw0f91PfrXfMtLCy@cluster0.ctbhh4w.mongodb.net/majorproject?retryWrites=true&w=majority&appName=Cluster0";

const JWT_SECRET = "your_jwt_secret"; // Keep it secure

const initializeDb = async () => {
  try {
    await mongoose.connect(mongoose_url);
    console.log("MongoDB connected");
  } catch (e) {
    console.log(e);
  }
};

initializeDb();

// -------------------- Middleware to Authenticate User Role --------------------
const authenticateRole = (allowedRoles) => (req, res, next) => {
  const authHeader = req.headers['authorization'];
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (!allowedRoles.includes(decoded.role)) {
      return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
    }

    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// -------------------- Login Route --------------------
app.post('/login', async (req, res) => {
  const { email, password, role } = req.body;

  console.log("Request Body:", req.body);

  try {
    const user = await User.findOne({ email });
    console.log("Found User:", user);

    if (!user) {
      console.log("No user found with this email");
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Password Match:", isPasswordValid);

    if (!isPasswordValid) {
      console.log("Password mismatch");
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (role && user.role !== role) {
      console.log(`Role mismatch: Expected ${role}, Found ${user.role}`);
      return res.status(401).json({ message: 'Role mismatch' });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({ token, role: user.role });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Error logging in' });
  }
});



// -------------------- Protected Routes --------------------
app.get('/admin-data', authenticateRole(['admin']), async (req, res) => {
  try {
    const events = await Event.find();
    res.json(events);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching data' });
  }
});



app.get('/api/events/grouped', async (req, res) => {
  try {
    const events = await Event.aggregate([
      {
        $group: {
          _id: '$department',
          events: { $push: '$$ROOT' }
        }
      }
    ]);
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get('/events', async (req, res) => {
  try {
    const events = await Event.find();
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

app.get('/events-by-category', async (req, res) => {
  try {
    const eventsByCategory = await Event.aggregate([
      { $group: { _id: '$department', events: { $push: '$$ROOT' } } }
    ]);
    res.status(200).json(eventsByCategory);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/events/:categoryId', async (req, res) => {
  const { categoryId } = req.params;

  try {
    const events = await Event.find({ department: categoryId });
    
    if (!events || events.length === 0) {
      return res.status(404).json({ message: 'No events found for this category' });
    }

    res.status(200).json(events);
  } catch (error) {
    console.error('Error fetching events by category:', error);
    res.status(500).json({ message: 'Failed to fetch events by category' });
  }
});


app.get('/manager-data', authenticateRole(['manager']), async (req, res) => {
  try {
    const events = await Event.find();
    res.json(events);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching data' });
  }
});

app.get('/volunteer-data', authenticateRole(['volunteer']), async (req, res) => {
  try {
    const events = await Event.find();
    res.json(events);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching data' });
  }
});

// -------------------- Signup Route --------------------
app.post('/signup', async (req, res) => {
  try {
    const { name, username, email, password, phone, role, occupation, department, studentDetails } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      username,
      email,
      password: hashedPassword,
      phone,
      role,
      occupation,
      department,
      studentDetails: occupation === 'student' ? studentDetails : undefined
    });

    await newUser.save();

    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to register user' });
  }
});



// -------------------- Create Event --------------------
app.post('/events', authenticateRole(['admin']), async (req, res) => {
  try {
    const event = new Event(req.body);
    await event.save();
    res.status(201).json(event);
  } catch (error) {
    res.status(500).json({ message: 'Failed to create event' });
  }
});

// -------------------- Update Event --------------------
app.put('/events/:id', authenticateRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const updatedEvent = await Event.findByIdAndUpdate(id, req.body, { new: true });
    res.status(200).json(updatedEvent);
  } catch (error) {
    res.status(500).json({ message: 'Failed to update event' });
  }
});

// -------------------- Delete Event --------------------
app.delete('/events/:id', authenticateRole(['admin']), async (req, res) => {
  try {
    await Event.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: 'Event deleted' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete event' });
  }
});

// -------------------- Assign Manager Role --------------------
app.post('/users/:id/assign-role', authenticateRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByIdAndUpdate(id, { role: 'manager' }, { new: true });
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: 'Failed to assign role' });
  }
});

// -------------------- Remove Manager Role --------------------
app.post('/users/:id/remove-role', authenticateRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByIdAndUpdate(id, { role: 'user' }, { new: true });
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: 'Failed to remove role' });
  }
});

// -------------------- Get Manager Requests --------------------
app.get('/manager-requests', authenticateRole(['admin']), async (req, res) => {
  try {
    const requests = await User.find({ roleRequest: 'manager' });
    res.json(requests);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch requests' });
  }
});

// -------------------- Approve Manager Request --------------------
app.post('/manager-requests/:id/approve', authenticateRole(['admin']), async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { role: 'manager', roleRequest: null });
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: 'Failed to approve request' });
  }
});

// -------------------- Reject Manager Request --------------------
app.post('/manager-requests/:id/reject', authenticateRole(['admin']), async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { roleRequest: null });
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: 'Failed to reject request' });
  }
});

// -------------------- Get All Users --------------------
app.get('/users', authenticateRole(['admin']), async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

// -------------------- Delete User --------------------
app.delete('/users/:id', authenticateRole(['admin']), async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: 'User deleted' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete user' });
  }
});





app.put('/users/:id/updateRole', authenticateRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body; // New role to be assigned

    if (!role) {
      return res.status(400).json({ message: 'Role is required' });
    }

    const updatedUser = await User.findByIdAndUpdate(
      id,
      { role },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'User role updated successfully', user: updatedUser });
  } catch (error) {
    console.error('Error updating user role:', error);
    res.status(500).json({ message: 'Failed to update user role' });
  }
});


app.get('/volunteers', authenticateRole(['admin']), async (req, res) => {
  try {
      const volunteers = await User.find({ role: 'volunteer' }).select('-password');
      res.status(200).json(volunteers);
  } catch (error) {
      console.error('Error fetching volunteers:', error);
      res.status(500).json({ error: 'Internal server error' });
  }
});

app.get("/api/events", async (req, res) => {
  try {
    const events = await Event.find();
    res.json(events);
  } catch (error) {
    res.status(500).json({ message: "Error fetching events" });
  }
});

// Delete event by ID
app.delete("/api/events/:id", async (req, res) => {
  try {
    await Event.findByIdAndDelete(req.params.id);
    res.json({ message: "Event deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting event" });
  }
});

app.put("/api/events/:id", async (req, res) => {
  try {
    const event = await Event.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(event);
  } catch (err) {
    res.status(500).json({ message: "Error updating event" });
  }
});

app.get("/api/events/:id", async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }
    res.json(event);
  } catch (err) {
    console.error("Error fetching event:", err);
    res.status(500).json({ message: "Server Error" });
  }
});

app.get('/api/users/managers', async (req, res) => {
  try {
      const { search } = req.query;
      const managers = await User.find({
          role: 'manager',
          $or: [
              { name: { $regex: search, $options: 'i' } },
              { email: { $regex: search, $options: 'i' } }
          ]
      });
      res.json(managers);
  } catch (err) {
      res.status(500).json({ error: 'Failed to search managers' });
  }
});
app.get('/api/users/volunteers', async (req, res) => {
  try {
      const { search } = req.query;
      const volunteers = await User.find({
          role: 'volunteer',
          $or: [
              { name: { $regex: search, $options: 'i' } },
              { email: { $regex: search, $options: 'i' } }
          ]
      });
      res.json(volunteers);
  } catch (err) {
      res.status(500).json({ error: 'Failed to search volunteers' });
  }
});


// Verify Token Route
app.get("/auth/verify", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    return res.json({ role: decoded.role });
  });
});


app.listen(3001, () => {
  console.log("Running at 3001");
});
