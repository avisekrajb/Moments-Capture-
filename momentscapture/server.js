const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Environment variables
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/photographer_app';
const JWT_SECRET = process.env.JWT_SECRET || 'photographer_app_secret_key_2024';
const EMAIL_USER = process.env.EMAIL_USER || 'abhishekrajbanshi999@gmail.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'your_app_password_here';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// MongoDB Connection
console.log('🔗 Connecting to MongoDB Atlas...');

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('✅ Connected to MongoDB Atlas successfully');
})
.catch(err => {
    console.error('❌ MongoDB connection failed:', err);
    process.exit(1);
});

// ==================== MONGODB SCHEMAS ====================

// Store images/files as buffers in MongoDB
const imageSchema = new mongoose.Schema({
    filename: { type: String, required: true },
    originalName: { type: String, required: true },
    mimeType: { type: String, required: true },
    buffer: { type: Buffer, required: true }, // Store file content
    size: { type: Number, required: true },
    uploadDate: { type: Date, default: Date.now }
});

const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    address: { type: String, required: true },
    phone: { type: String, required: true },
    profilePhoto: { type: mongoose.Schema.Types.ObjectId, ref: 'Image' }, // Reference to image
    role: { type: String, default: 'user' },
    createdAt: { type: Date, default: Date.now }
});

const bookingSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    services: [{ type: String, required: true }],
    date: { type: Date, required: true },
    time: { type: String, required: true },
    location: { type: String, required: true },
    specialRequests: { type: String },
    amount: { type: Number, required: true },
    status: { type: String, default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const contactSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    message: { type: String, required: true },
    adminReply: { type: String },
    status: { type: String, default: 'pending' },
    date: { type: Date, default: Date.now }
});

const carouselSchema = new mongoose.Schema({
    image: { type: mongoose.Schema.Types.ObjectId, ref: 'Image', required: true }, // Reference to image
    title: { type: String, required: true },
    description: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const serviceSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true },
    image: { type: mongoose.Schema.Types.ObjectId, ref: 'Image' }, // Reference to image
    isNew: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const visitSchema = new mongoose.Schema({
    count: { type: Number, default: 0 },
    lastUpdated: { type: Date, default: Date.now }
});

const portfolioSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    category: { type: String, required: true },
    image: { type: mongoose.Schema.Types.ObjectId, ref: 'Image', required: true }, // Reference to image
    type: { type: String, enum: ['photo', 'video'], default: 'photo' },
    likes: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

// MongoDB Models
const Image = mongoose.model('Image', imageSchema);
const User = mongoose.model('User', userSchema);
const Booking = mongoose.model('Booking', bookingSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Carousel = mongoose.model('Carousel', carouselSchema);
const Service = mongoose.model('Service', serviceSchema);
const Visit = mongoose.model('Visit', visitSchema);
const Portfolio = mongoose.model('Portfolio', portfolioSchema);

// ==================== FILE STORAGE IN MONGODB ====================

// Store files in memory (will be saved to MongoDB)
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image and video files are allowed!'), false);
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
});

// ==================== UTILITY FUNCTIONS ====================

// Save image to MongoDB
const saveImageToDB = async (file) => {
    const image = new Image({
        filename: `${Date.now()}-${file.originalname}`,
        originalName: file.originalname,
        mimeType: file.mimetype,
        buffer: file.buffer,
        size: file.size
    });
    
    return await image.save();
};

// Get image URL
const getImageUrl = (imageId) => {
    return `/api/images/${imageId}`;
};

// Serve image from MongoDB
app.get('/api/images/:id', async (req, res) => {
    try {
        const image = await Image.findById(req.params.id);
        
        if (!image) {
            return res.status(404).json({ error: 'Image not found' });
        }

        res.setHeader('Content-Type', image.mimeType);
        res.setHeader('Content-Length', image.size);
        res.setHeader('Content-Disposition', `inline; filename="${image.originalName}"`);
        
        res.send(image.buffer);
    } catch (error) {
        console.error('Error serving image:', error);
        res.status(500).json({ error: 'Failed to serve image' });
    }
});

// Email transporter configuration
const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS
    }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// User middleware
const requireUser = (req, res, next) => {
    if (req.user.role === 'admin') {
        return res.status(403).json({ error: 'Admin cannot access user features' });
    }
    next();
};

// Visit counter middleware
const countVisit = async (req, res, next) => {
    try {
        let visit = await Visit.findOne();
        if (!visit) {
            visit = await Visit.create({ count: 1 });
        } else {
            visit.count += 1;
            visit.lastUpdated = new Date();
            await visit.save();
        }
        next();
    } catch (error) {
        console.error('Visit count error:', error);
        next();
    }
};

// ==================== INITIALIZE DATA ====================

const initializeData = async () => {
    try {
        // Create admin user
        const adminExists = await User.findOne({ email: 'a@gmail.com' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('12345', 10);
            await User.create({
                fullName: 'Admin User',
                email: 'a@gmail.com',
                password: hashedPassword,
                address: 'Admin Address',
                phone: '0000000000',
                role: 'admin'
            });
            console.log('👑 Admin user created: a@gmail.com / 12345');
        }

        // Create default services
        const defaultServices = [
            {
                name: 'Wedding Photography',
                description: 'Full day coverage with 2 photographers',
                price: 500,
                isNew: false
            },
            {
                name: 'Photo Shoots',
                description: '2-hour professional photo session',
                price: 200,
                isNew: false
            },
            {
                name: 'Program Events',
                description: 'Event coverage up to 4 hours',
                price: 300,
                isNew: false
            },
            {
                name: 'Sponsorship Events',
                description: 'Corporate event photography',
                price: 150,
                isNew: false
            }
        ];

        for (const serviceData of defaultServices) {
            const serviceExists = await Service.findOne({ name: serviceData.name });
            if (!serviceExists) {
                await Service.create(serviceData);
            }
        }

        // Create default carousel images (using placeholder URLs)
        const defaultCarousel = [
            {
                title: 'Wedding Photography',
                description: 'Capture your special day with our professional wedding photography services'
            },
            {
                title: 'Portrait Sessions',
                description: 'Professional portrait photography for individuals and families'
            },
            {
                title: 'Event Photography',
                description: 'Document your corporate events, parties, and special occasions'
            },
            {
                title: 'Commercial Photography',
                description: 'High-quality product and commercial photography for businesses'
            }
        ];

        const carouselCount = await Carousel.countDocuments();
        if (carouselCount === 0) {
            // Create carousel without images initially
            for (const carouselData of defaultCarousel) {
                await Carousel.create(carouselData);
            }
            console.log('🖼️ Default carousel created (add images through admin panel)');
        }

        // Initialize visit counter
        const visitExists = await Visit.findOne();
        if (!visitExists) {
            await Visit.create({ count: 0 });
        }

        console.log('✅ Default data initialized successfully');
    } catch (error) {
        console.error('❌ Error initializing data:', error);
    }
};

// ==================== ROUTES ====================

// Health check
app.get('/api/health', async (req, res) => {
    try {
        const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
        const userCount = await User.countDocuments();
        const bookingCount = await Booking.countDocuments();
        const serviceCount = await Service.countDocuments();
        const imageCount = await Image.countDocuments();
        
        res.json({
            status: 'OK',
            database: dbStatus,
            users: userCount,
            bookings: bookingCount,
            services: serviceCount,
            images: imageCount,
            storage: 'MongoDB Atlas (Permanent)'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Serve main application with visit counting
app.get('/', countVisit, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Get visit count
app.get('/api/visits', async (req, res) => {
    try {
        const visit = await Visit.findOne();
        res.json({ count: visit ? visit.count : 0 });
    } catch (error) {
        console.error('Visit count error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Count website visit
app.post('/api/visits', async (req, res) => {
    try {
        let visit = await Visit.findOne();
        if (!visit) {
            visit = await Visit.create({ count: 1 });
        } else {
            visit.count += 1;
            visit.lastUpdated = new Date();
            await visit.save();
        }
        res.json({ 
            message: 'Visit counted successfully',
            count: visit.count 
        });
    } catch (error) {
        console.error('Visit count error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Registration with Email
app.post('/api/register', async (req, res) => {
    try {
        const { fullName, email, password, address, phone } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists with this email' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const newUser = await User.create({
            fullName,
            email,
            password: hashedPassword,
            address,
            phone
        });

        // Send welcome email
        try {
            await transporter.sendMail({
                from: EMAIL_USER,
                to: email,
                subject: 'Welcome to Capture Moments Photography',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                        <div style="text-align: center; background: linear-gradient(135deg, #FF6B6B, #4ECDC4); padding: 20px; border-radius: 10px 10px 0 0;">
                            <h1 style="color: white; margin: 0;">Capture Moments</h1>
                        </div>
                        <div style="padding: 20px;">
                            <h2 style="color: #FF6B6B;">Welcome, ${fullName}!</h2>
                            <p>Thank you for registering with Capture Moments Photography. We're excited to have you on board!</p>
                            <p>Your account has been successfully created with the following details:</p>
                            <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                <p><strong>Email:</strong> ${email}</p>
                                <p><strong>Phone:</strong> ${phone}</p>
                                <p><strong>Address:</strong> ${address}</p>
                            </div>
                            <p>You can now login to your account and start booking our photography services.</p>
                            <p>If you have any questions, feel free to contact us.</p>
                            <p>Best regards,<br><strong>The Capture Moments Team</strong></p>
                        </div>
                        <div style="text-align: center; padding: 20px; background: #f5f5f5; border-radius: 0 0 10px 10px;">
                            <p style="color: #666; font-size: 12px; margin: 0;">
                                This is an automated message. Please do not reply to this email.
                            </p>
                        </div>
                    </div>
                `
            });
            console.log('📧 Welcome email sent to:', email);
        } catch (emailError) {
            console.error('Failed to send welcome email:', emailError);
        }

        res.status(201).json({ 
            message: 'User registered successfully',
            user: {
                id: newUser._id,
                fullName: newUser.fullName,
                email: newUser.email
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // Generate token
        const token = jwt.sign(
            { 
                id: user._id, 
                email: user.email, 
                role: user.role 
            }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        // Get profile photo URL if exists
        let profilePhotoUrl = null;
        if (user.profilePhoto) {
            profilePhotoUrl = getImageUrl(user.profilePhoto);
        }

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                profilePhoto: profilePhotoUrl
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
            .select('-password')
            .populate('profilePhoto');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Convert to response format
        const userResponse = user.toObject();
        if (user.profilePhoto) {
            userResponse.profilePhoto = getImageUrl(user.profilePhoto._id);
        }

        res.json(userResponse);
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update user profile with photo
app.put('/api/profile', authenticateToken, requireUser, upload.single('profilePhoto'), async (req, res) => {
    try {
        const { fullName, address, phone } = req.body;
        const updateData = { fullName, address, phone };
        
        if (req.file) {
            // Save new profile photo to MongoDB
            const savedImage = await saveImageToDB(req.file);
            updateData.profilePhoto = savedImage._id;
            
            // Delete old profile photo if exists
            const oldUser = await User.findById(req.user.id);
            if (oldUser.profilePhoto) {
                await Image.findByIdAndDelete(oldUser.profilePhoto);
            }
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.user.id,
            updateData,
            { new: true }
        ).select('-password').populate('profilePhoto');

        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Convert to response format
        const userResponse = updatedUser.toObject();
        if (updatedUser.profilePhoto) {
            userResponse.profilePhoto = getImageUrl(updatedUser.profilePhoto._id);
        }

        res.json({ 
            message: 'Profile updated successfully',
            user: userResponse
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Contact form submission
app.post('/api/contact', authenticateToken, requireUser, async (req, res) => {
    try {
        const { name, email, phone, message } = req.body;

        const newContact = await Contact.create({
            userId: req.user.id,
            name,
            email,
            phone,
            message
        });

        // Send confirmation email to user
        try {
            await transporter.sendMail({
                from: EMAIL_USER,
                to: email,
                subject: 'Message Received - Capture Moments',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                        <div style="text-align: center; background: linear-gradient(135deg, #FF6B6B, #4ECDC4); padding: 20px; border-radius: 10px 10px 0 0;">
                            <h1 style="color: white; margin: 0;">Capture Moments</h1>
                        </div>
                        <div style="padding: 20px;">
                            <h2 style="color: #FF6B6B;">Message Received</h2>
                            <p>Dear ${name},</p>
                            <p>Thank you for contacting Capture Moments Photography. We have received your message and will get back to you shortly.</p>
                            <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                <p><strong>Your Message:</strong></p>
                                <p style="background: white; padding: 10px; border-radius: 5px;">${message}</p>
                            </div>
                            <p>We typically respond within 24 hours. If you have any urgent inquiries, please call us at +1 (555) 123-4567.</p>
                            <p>Best regards,<br><strong>The Capture Moments Team</strong></p>
                        </div>
                        <div style="text-align: center; padding: 20px; background: #f5f5f5; border-radius: 0 0 10px 10px;">
                            <p style="color: #666; font-size: 12px; margin: 0;">
                                This is an automated message. Please do not reply to this email.
                            </p>
                        </div>
                    </div>
                `
            });
            console.log('📧 Contact confirmation email sent to:', email);
        } catch (emailError) {
            console.error('Failed to send contact confirmation email:', emailError);
        }

        res.json({ 
            message: 'Message sent successfully',
            contact: newContact
        });
    } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create booking (only for users, not admin)
app.post('/api/bookings', authenticateToken, requireUser, async (req, res) => {
    try {
        const { services, date, time, location, specialRequests, amount } = req.body;

        const newBooking = await Booking.create({
            userId: req.user.id,
            services,
            date,
            time,
            location,
            specialRequests,
            amount
        });

        // Get user details for email
        const user = await User.findById(req.user.id);
        
        // Send booking confirmation email
        try {
            await transporter.sendMail({
                from: EMAIL_USER,
                to: user.email,
                subject: 'Booking Confirmation - Capture Moments',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                        <div style="text-align: center; background: linear-gradient(135deg, #FF6B6B, #4ECDC4); padding: 20px; border-radius: 10px 10px 0 0;">
                            <h1 style="color: white; margin: 0;">Capture Moments</h1>
                        </div>
                        <div style="padding: 20px;">
                            <h2 style="color: #FF6B6B;">Booking Confirmed!</h2>
                            <p>Dear ${user.fullName},</p>
                            <p>Your photography booking has been successfully created. Here are the details:</p>
                            <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                <p><strong>Services:</strong> ${services.join(', ')}</p>
                                <p><strong>Date:</strong> ${new Date(date).toLocaleDateString()}</p>
                                <p><strong>Time:</strong> ${time}</p>
                                <p><strong>Location:</strong> ${location}</p>
                                <p><strong>Amount:</strong> $${amount}</p>
                                ${specialRequests ? `<p><strong>Special Requests:</strong> ${specialRequests}</p>` : ''}
                                <p><strong>Status:</strong> <span style="color: #FFD166; font-weight: bold;">PENDING</span></p>
                            </div>
                            <p>We will review your booking and confirm it shortly. You can check the status in your account.</p>
                            <p>If you have any questions, please don't hesitate to contact us.</p>
                            <p>Best regards,<br><strong>The Capture Moments Team</strong></p>
                        </div>
                        <div style="text-align: center; padding: 20px; background: #f5f5f5; border-radius: 0 0 10px 10px;">
                            <p style="color: #666; font-size: 12px; margin: 0;">
                                This is an automated message. Please do not reply to this email.
                            </p>
                        </div>
                    </div>
                `
            });
            console.log('📧 Booking confirmation email sent to:', user.email);
        } catch (emailError) {
            console.error('Failed to send booking confirmation email:', emailError);
        }

        res.status(201).json({ 
            message: 'Booking created successfully',
            booking: newBooking
        });
    } catch (error) {
        console.error('Booking creation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user bookings
app.get('/api/my-bookings', authenticateToken, requireUser, async (req, res) => {
    try {
        const bookings = await Booking.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json(bookings);
    } catch (error) {
        console.error('Bookings error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user messages
app.get('/api/my-messages', authenticateToken, requireUser, async (req, res) => {
    try {
        const messages = await Contact.find({ userId: req.user.id }).sort({ date: -1 });
        res.json(messages);
    } catch (error) {
        console.error('Messages error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete user message
app.delete('/api/my-messages/:id', authenticateToken, requireUser, async (req, res) => {
    try {
        const message = await Contact.findOne({ _id: req.params.id, userId: req.user.id });
        
        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }

        await Contact.findByIdAndDelete(req.params.id);
        res.json({ message: 'Message deleted successfully' });
    } catch (error) {
        console.error('Message delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete booking
app.delete('/api/bookings/:id', authenticateToken, requireUser, async (req, res) => {
    try {
        const booking = await Booking.findOne({ _id: req.params.id, userId: req.user.id });
        
        if (!booking) {
            return res.status(404).json({ error: 'Booking not found' });
        }

        if (booking.status !== 'pending') {
            return res.status(400).json({ error: 'Only pending bookings can be deleted' });
        }

        await Booking.findByIdAndDelete(req.params.id);
        res.json({ message: 'Booking deleted successfully' });
    } catch (error) {
        console.error('Booking delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all services
app.get('/api/services', async (req, res) => {
    try {
        // Mark services as not new after 15 days
        await Service.updateMany(
            { 
                isNew: true, 
                createdAt: { $lt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000) }
            },
            { $set: { isNew: false } }
        );

        const services = await Service.find()
            .populate('image')
            .sort({ isNew: -1, createdAt: -1 });

        // Convert to response format with image URLs
        const servicesWithUrls = services.map(service => {
            const serviceObj = service.toObject();
            if (service.image) {
                serviceObj.image = getImageUrl(service.image._id);
            }
            return serviceObj;
        });

        res.json(servicesWithUrls);
    } catch (error) {
        console.error('Services error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get carousel images
app.get('/api/carousel', async (req, res) => {
    try {
        const images = await Carousel.find()
            .populate('image')
            .sort({ createdAt: -1 })
            .limit(4);

        // Convert to response format with image URLs
        const carouselWithUrls = images.map(item => {
            const itemObj = item.toObject();
            if (item.image) {
                itemObj.image = getImageUrl(item.image._id);
            }
            return itemObj;
        });

        res.json(carouselWithUrls);
    } catch (error) {
        console.error('Carousel error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==================== ADMIN ROUTES ====================

// Get all bookings (admin only)
app.get('/api/admin/bookings', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const bookings = await Booking.find()
            .populate('userId', 'fullName email phone')
            .sort({ createdAt: -1 });
        res.json(bookings);
    } catch (error) {
        console.error('Admin bookings error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update booking status (admin only) with Email
app.put('/api/admin/bookings/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.body;

        const booking = await Booking.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        ).populate('userId', 'fullName email');

        if (!booking) {
            return res.status(404).json({ error: 'Booking not found' });
        }

        // Send status update email
        try {
            await transporter.sendMail({
                from: EMAIL_USER,
                to: booking.userId.email,
                subject: `Booking Status Update - ${booking.userId.fullName}`,
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                        <div style="text-align: center; background: linear-gradient(135deg, #FF6B6B, #4ECDC4); padding: 20px; border-radius: 10px 10px 0 0;">
                            <h1 style="color: white; margin: 0;">Capture Moments</h1>
                        </div>
                        <div style="padding: 20px;">
                            <h2 style="color: #FF6B6B;">Booking Status Update</h2>
                            <p>Dear ${booking.userId.fullName},</p>
                            <p>Your booking status has been updated:</p>
                            <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                <p><strong>Services:</strong> ${booking.services.join(', ')}</p>
                                <p><strong>Date:</strong> ${new Date(booking.date).toLocaleDateString()}</p>
                                <p><strong>Time:</strong> ${booking.time}</p>
                                <p><strong>Location:</strong> ${booking.location}</p>
                                <p><strong>New Status:</strong> 
                                    <span style="color: ${
                                        status === 'confirmed' ? '#06D6A0' : 
                                        status === 'completed' ? '#4ECDC4' : 
                                        status === 'rejected' ? '#EF476F' : '#FFD166'
                                    }; font-weight: bold;">
                                        ${status.toUpperCase()}
                                    </span>
                                </p>
                            </div>
                            ${status === 'completed' ? 
                                '<p>Your photography session has been completed successfully. Thank you for choosing Capture Moments!</p>' : 
                                status === 'confirmed' ?
                                '<p>Your booking has been confirmed! We look forward to capturing your special moments.</p>' :
                                status === 'rejected' ?
                                '<p>Unfortunately, we cannot accommodate your booking at this time. Please contact us for alternative options.</p>' :
                                ''
                            }
                            <p>If you have any questions, please don't hesitate to contact us.</p>
                            <p>Best regards,<br><strong>The Capture Moments Team</strong></p>
                        </div>
                        <div style="text-align: center; padding: 20px; background: #f5f5f5; border-radius: 0 0 10px 10px;">
                            <p style="color: #666; font-size: 12px; margin: 0;">
                                This is an automated message. Please do not reply to this email.
                            </p>
                        </div>
                    </div>
                `
            });
            console.log('📧 Booking status update email sent to:', booking.userId.email);
        } catch (emailError) {
            console.error('Failed to send status update email:', emailError);
        }

        res.json({ 
            message: 'Booking status updated successfully',
            booking
        });
    } catch (error) {
        console.error('Booking update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete booking (admin only)
app.delete('/api/admin/bookings/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const booking = await Booking.findByIdAndDelete(req.params.id);
        if (!booking) {
            return res.status(404).json({ error: 'Booking not found' });
        }

        res.json({ message: 'Booking deleted successfully' });
    } catch (error) {
        console.error('Booking delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({ role: 'user' }).select('-password').sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update user email (admin only)
app.put('/api/admin/users/:id/email', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { email } = req.body;

        // Check if email already exists
        const existingUser = await User.findOne({ email, _id: { $ne: req.params.id } });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            { email },
            { new: true }
        ).select('-password');

        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ 
            message: 'User email updated successfully',
            user: updatedUser
        });
    } catch (error) {
        console.error('User update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete user (admin only)
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Also delete user's bookings and messages
        await Booking.deleteMany({ userId: req.params.id });
        await Contact.deleteMany({ userId: req.params.id });

        // Delete user's profile photo if exists
        if (user.profilePhoto) {
            await Image.findByIdAndDelete(user.profilePhoto);
        }

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('User delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all contact messages (admin only)
app.get('/api/admin/messages', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const messages = await Contact.find().populate('userId', 'fullName email').sort({ date: -1 });
        res.json(messages);
    } catch (error) {
        console.error('Admin messages error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update message status and reply (admin only) with Email
app.put('/api/admin/messages/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, adminReply } = req.body;

        const message = await Contact.findByIdAndUpdate(
            req.params.id,
            { status, adminReply },
            { new: true }
        ).populate('userId', 'fullName email');

        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }

        // Send reply email if admin replied
        if (adminReply) {
            try {
                await transporter.sendMail({
                    from: EMAIL_USER,
                    to: message.email,
                    subject: `Reply to your message - Capture Moments`,
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                            <div style="text-align: center; background: linear-gradient(135deg, #FF6B6B, #4ECDC4); padding: 20px; border-radius: 10px 10px 0 0;">
                                <h1 style="color: white; margin: 0;">Capture Moments</h1>
                            </div>
                            <div style="padding: 20px;">
                                <h2 style="color: #FF6B6B;">Response to Your Message</h2>
                                <p>Dear ${message.name},</p>
                                <p>Thank you for contacting us. Here is our response to your message:</p>
                                <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                    <p><strong>Your Original Message:</strong></p>
                                    <p style="background: white; padding: 10px; border-left: 4px solid #FF6B6B;">${message.message}</p>
                                    <p><strong>Our Response:</strong></p>
                                    <p style="background: white; padding: 10px; border-left: 4px solid #4ECDC4;">${adminReply}</p>
                                </div>
                                <p>If you have any further questions, please don't hesitate to contact us.</p>
                                <p>Best regards,<br><strong>The Capture Moments Team</strong></p>
                            </div>
                            <div style="text-align: center; padding: 20px; background: #f5f5f5; border-radius: 0 0 10px 10px;">
                                <p style="color: #666; font-size: 12px; margin: 0;">
                                    This is an automated message. Please do not reply to this email.
                                </p>
                            </div>
                        </div>
                    `
                });
                console.log('📧 Reply email sent to:', message.email);
            } catch (emailError) {
                console.error('Failed to send reply email:', emailError);
            }
        }

        res.json({ 
            message: 'Message updated successfully',
            contact: message
        });
    } catch (error) {
        console.error('Message update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add carousel image (admin only) - MAX 4 IMAGES
app.post('/api/admin/carousel', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
    try {
        const count = await Carousel.countDocuments();
        if (count >= 4) {
            return res.status(400).json({ error: 'Maximum 4 carousel images allowed. Please delete an existing image first.' });
        }

        if (!req.file) {
            return res.status(400).json({ error: 'Image file is required' });
        }

        const { title, description } = req.body;

        // Save image to MongoDB
        const savedImage = await saveImageToDB(req.file);

        const newImage = await Carousel.create({
            image: savedImage._id,
            title: title || 'New Carousel Image',
            description: description || 'Carousel image description'
        });

        res.status(201).json({ 
            message: 'Carousel image added successfully',
            image: {
                _id: newImage._id,
                title: newImage.title,
                description: newImage.description,
                image: getImageUrl(savedImage._id)
            }
        });
    } catch (error) {
        console.error('Carousel image upload error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete carousel image (admin only)
app.delete('/api/admin/carousel/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const carouselItem = await Carousel.findById(req.params.id);
        if (!carouselItem) {
            return res.status(404).json({ error: 'Carousel item not found' });
        }

        // Delete the associated image
        if (carouselItem.image) {
            await Image.findByIdAndDelete(carouselItem.image);
        }

        await Carousel.findByIdAndDelete(req.params.id);

        res.json({ message: 'Carousel image deleted successfully' });
    } catch (error) {
        console.error('Carousel delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add new service (admin only)
app.post('/api/admin/services', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
    try {
        const { name, description, price } = req.body;

        if (!name || !description || !price) {
            return res.status(400).json({ error: 'Name, description and price are required' });
        }

        // Check if service already exists
        const existingService = await Service.findOne({ name });
        if (existingService) {
            return res.status(400).json({ error: 'Service with this name already exists' });
        }

        const serviceData = {
            name,
            description,
            price: parseFloat(price),
            isNew: true
        };

        if (req.file) {
            // Save image to MongoDB
            const savedImage = await saveImageToDB(req.file);
            serviceData.image = savedImage._id;
        }

        const newService = await Service.create(serviceData);

        res.status(201).json({ 
            message: 'Service added successfully',
            service: {
                _id: newService._id,
                name: newService.name,
                description: newService.description,
                price: newService.price,
                isNew: newService.isNew,
                image: newService.image ? getImageUrl(newService.image) : null
            }
        });
    } catch (error) {
        console.error('Service creation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get single service (admin only)
app.get('/api/admin/services/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const service = await Service.findById(req.params.id).populate('image');
        if (!service) {
            return res.status(404).json({ error: 'Service not found' });
        }

        const serviceObj = service.toObject();
        if (service.image) {
            serviceObj.image = getImageUrl(service.image._id);
        }

        res.json(serviceObj);
    } catch (error) {
        console.error('Get service error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update service (admin only)
app.put('/api/admin/services/:id', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
    try {
        const { name, description, price, isNew } = req.body;
        
        const updateData = {
            name,
            description,
            price: parseFloat(price),
            isNew: isNew === 'true'
        };
        
        if (req.file) {
            // Save new image to MongoDB
            const savedImage = await saveImageToDB(req.file);
            updateData.image = savedImage._id;
            
            // Delete old image if exists
            const oldService = await Service.findById(req.params.id);
            if (oldService.image) {
                await Image.findByIdAndDelete(oldService.image);
            }
        }
        
        const updatedService = await Service.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true }
        ).populate('image');
        
        if (!updatedService) {
            return res.status(404).json({ error: 'Service not found' });
        }

        const serviceObj = updatedService.toObject();
        if (updatedService.image) {
            serviceObj.image = getImageUrl(updatedService.image._id);
        }
        
        res.json({ 
            message: 'Service updated successfully',
            service: serviceObj
        });
    } catch (error) {
        console.error('Service update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete service (admin only)
app.delete('/api/admin/services/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const service = await Service.findById(req.params.id);
        if (!service) {
            return res.status(404).json({ error: 'Service not found' });
        }

        // Delete associated image if exists
        if (service.image) {
            await Image.findByIdAndDelete(service.image);
        }

        await Service.findByIdAndDelete(req.params.id);

        res.json({ message: 'Service deleted successfully' });
    } catch (error) {
        console.error('Service delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==================== PORTFOLIO ROUTES ====================

// Get portfolio items
app.get('/api/portfolio', async (req, res) => {
    try {
        const { category, type } = req.query;
        let query = {};
        
        if (category && category !== 'all') {
            query.category = category;
        }
        
        if (type) {
            query.type = type;
        }

        const portfolioItems = await Portfolio.find(query)
            .populate('image')
            .sort({ createdAt: -1 });

        const itemsWithUrls = portfolioItems.map(item => {
            const itemObj = item.toObject();
            if (item.image) {
                itemObj.image = getImageUrl(item.image._id);
            }
            return itemObj;
        });

        res.json(itemsWithUrls);
    } catch (error) {
        console.error('Portfolio error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add portfolio item (admin only)
app.post('/api/admin/portfolio', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
    try {
        const { title, description, category, type } = req.body;

        if (!req.file) {
            return res.status(400).json({ error: 'Image file is required' });
        }

        // Save image to MongoDB
        const savedImage = await saveImageToDB(req.file);

        const newPortfolioItem = await Portfolio.create({
            title,
            description,
            category,
            type: type || 'photo',
            image: savedImage._id
        });

        res.status(201).json({ 
            message: 'Portfolio item added successfully',
            item: {
                _id: newPortfolioItem._id,
                title: newPortfolioItem.title,
                description: newPortfolioItem.description,
                category: newPortfolioItem.category,
                type: newPortfolioItem.type,
                image: getImageUrl(savedImage._id),
                likes: newPortfolioItem.likes
            }
        });
    } catch (error) {
        console.error('Portfolio upload error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete portfolio item (admin only)
app.delete('/api/admin/portfolio/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const portfolioItem = await Portfolio.findById(req.params.id);
        if (!portfolioItem) {
            return res.status(404).json({ error: 'Portfolio item not found' });
        }

        // Delete associated image
        if (portfolioItem.image) {
            await Image.findByIdAndDelete(portfolioItem.image);
        }

        await Portfolio.findByIdAndDelete(req.params.id);

        res.json({ message: 'Portfolio item deleted successfully' });
    } catch (error) {
        console.error('Portfolio delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==================== ERROR HANDLING ====================

// Error handling middleware
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
        }
    }
    
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// ==================== START SERVER ====================

// Initialize server
const startServer = async () => {
    await initializeData();
    
    app.listen(PORT, '0.0.0.0', () => {
        console.log('='.repeat(60));
        console.log('🚀 CAPTURE MOMENTS PHOTOGRAPHY - MONGODB COMPLETE SOLUTION');
        console.log('='.repeat(60));
        console.log(`✅ Server running on port: ${PORT}`);
        console.log(`💾 All files stored in MongoDB Atlas (Permanent Storage)`);
        console.log(`🖼️ Images, photos, files survive server restarts`);
        console.log(`📊 Database: ${MONGODB_URI.split('@')[1]}`);
        console.log(`👑 Admin: a@gmail.com / 12345`);
        console.log('='.repeat(60));
    });
};

startServer();

module.exports = app;
