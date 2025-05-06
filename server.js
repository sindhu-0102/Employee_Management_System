import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';

const app = express();
app.use(cors({
    origin: ["http://localhost:5173"],
    methods: ["POST", "GET", "PUT", "DELETE"],
    credentials: true
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

mongoose.connect("mongodb://localhost:27017/management", {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Connected to MongoDB");
    createInitialAdmin();  // Create admin at startup
}).catch(err => console.error("Error connecting to MongoDB:", err));

// Schema and Models
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    role: String
});

const employeeSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    address: String,
    salary: Number,
    image: String
});

const User = mongoose.model('User', userSchema);
const Employee = mongoose.model('Employee', employeeSchema);

const createInitialAdmin = async () => {
    const adminEmail = "admin@gmail.com";
    const adminPassword = "12345";
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (!existingAdmin) {
        const admin = new User({
            email: adminEmail,
            password: hashedPassword,
            role: "admin"
        });
        await admin.save();
        console.log("Initial admin created with email:", adminEmail);
    } else {
        console.log("Admin already exists with email:", adminEmail);
    }
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/images'),
    filename: (req, file, cb) => cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

// Routes

app.get('/getEmployee', async (req, res) => {
    try {
        const employees = await Employee.find({});
        res.json({ Status: "Success", Result: employees });
    } catch (err) {
        res.json({ Error: "Error retrieving employees from MongoDB" });
    }
});

app.get('/get/:id', async (req, res) => {
    try {
        const employee = await Employee.findById(req.params.id);
        res.json({ Status: "Success", Result: employee });
    } catch (err) {
        res.json({ Error: "Error retrieving employee from MongoDB" });
    }
});

app.put('/update/:id', async (req, res) => {
    try {
        await Employee.findByIdAndUpdate(req.params.id, { salary: req.body.salary });
        res.json({ Status: "Success" });
    } catch (err) {
        res.json({ Error: "Error updating employee in MongoDB" });
    }
});

app.delete('/delete/:id', async (req, res) => {
    try {
        await Employee.findByIdAndDelete(req.params.id);
        res.json({ Status: "Success" });
    } catch (err) {
        res.json({ Error: "Error deleting employee from MongoDB" });
    }
});

const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are not authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Invalid token" });
            req.role = decoded.role;
            req.id = decoded.id;
            next();
        });
    }
};

app.get('/dashboard', verifyUser, (req, res) => {
    res.json({ Status: "Success", role: req.role, id: req.id });
});

app.get('/adminCount', async (req, res) => {
    try {
        const adminCount = await User.countDocuments({ role: "admin" });
        res.json({ admin: adminCount });
    } catch (err) {
        res.json({ Error: "Error counting admins in MongoDB" });
    }
});

app.get('/employeeCount', async (req, res) => {
    try {
        const employeeCount = await Employee.countDocuments();
        res.json({ employee: employeeCount });
    } catch (err) {
        res.json({ Error: "Error counting employees in MongoDB" });
    }
});

app.get('/salary', async (req, res) => {
    try {
        const [{ sumOfSalary = 0 } = {}] = await Employee.aggregate([
            { $group: { _id: null, sumOfSalary: { $sum: "$salary" } } }
        ]);
        res.json({ sumOfSalary });
    } catch (err) {
        res.json({ Error: "Error summing salary in MongoDB" });
    }
});

app.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (user) {
            // Compare the entered password with the stored hashed password
            const isMatch = await bcrypt.compare(req.body.password, user.password);
            if (isMatch) {
                const token = jwt.sign({ role: "admin", id: user._id }, "jwt-secret-key", { expiresIn: '1d' });
                res.cookie('token', token);
                return res.json({ Status: "Success" });
            } else {
                return res.json({ Status: "Error", Error: "Wrong Email or Password" });
            }
        } else {
            return res.json({ Status: "Error", Error: "Wrong Email or Password" });
        }
    } catch (err) {
        return res.json({ Error: "Error in login query" });
    }
});


app.post('/employeelogin', async (req, res) => {
    try {
        const employee = await Employee.findOne({ email: req.body.email });
        if (employee) {
            const match = await bcrypt.compare(req.body.password, employee.password);
            if (match) {
                const token = jwt.sign({ role: "employee", id: employee._id }, "jwt-secret-key", { expiresIn: '1d' });
                res.cookie('token', token);
                res.json({ Status: "Success", id: employee._id });
            } else {
                res.json({ Status: "Error", Error: "Wrong Email or Password" });
            }
        } else {
            res.json({ Status: "Error", Error: "Wrong Email or Password" });
        }
    } catch (err) {
        res.json({ Error: "Error in employee login query" });
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ Status: "Success" });
});

app.post('/create', upload.single('image'), async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const employee = new Employee({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
            address: req.body.address,
            salary: req.body.salary,
            image: req.file.filename
        });
        await employee.save();
        res.json({ Status: "Success" });
    } catch (err) {
        res.json({ Error: "Error in creating employee in MongoDB" });
    }
});

app.listen(8081, () => {
    console.log("Server is running on port 8081");
});
