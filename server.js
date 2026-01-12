const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
require('dotenv').config();

const app = express();

/* =======================
   BASIC MIDDLEWARE
======================= */
app.use(cors());
app.use(express.json());

/* =======================
   ENV CHECK (SAFE LOG)
======================= */
console.log("🔎 MONGO_URI loaded:", !!process.env.MONGO_URI);
console.log("🔎 STRIPE KEY loaded:", !!process.env.STRIPE_SECRET_KEY);

/* =======================
/* =======================
    MONGODB CONNECTION
======================= */
mongoose.connect(process.env.MONGO_URI, {
    dbName: 'Acrylix' 
})
.then(() => console.log('✅ MongoDB Connected Successfully to Acrylix'))
.catch(err => console.error('❌ MongoDB Connection Error:', err.message));

/* =======================
   DB STATUS ROUTE (DEBUG)
======================= */
app.get('/api/db-status', (req, res) => {
    const state = mongoose.connection.readyState;
    res.json({
        mongoState: state,
        status:
            state === 1 ? "CONNECTED" :
            state === 2 ? "CONNECTING" :
            "NOT CONNECTED"
    });
});

/* =======================
   SCHEMAS
======================= */

// USER
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// ORDER
const orderSchema = new mongoose.Schema({
    items: Array,
    total: String,
    customerEmail: String,
    stripeSessionId: String,
    status: { type: String, default: 'Pending' },
    date: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

// INQUIRY
const inquirySchema = new mongoose.Schema({
    name: String,
    email: String,
    message: String,
    date: { type: Date, default: Date.now }
});
const Inquiry = mongoose.model('Inquiry', inquirySchema);

/* =======================
   AUTH MIDDLEWARE (JWT)
======================= */
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "No token provided" });

    const token = authHeader.split(" ")[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'SUPER_SECRET');
        req.userId = decoded.id;
        next();
    } catch {
        return res.status(401).json({ error: "Invalid or expired token" });
    }
};

/* =======================
   AUTH: LOGIN / REGISTER
======================= */
/* =======================
   REPLACE YOUR LOGIN ROUTE WITH THIS
======================= */
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "Missing email or password" });
        }

        let user = await User.findOne({ email });

        if (!user) {
            console.log("Creating new user...");
            const hashed = await bcrypt.hash(password, 10);
            user = await User.create({ email, password: hashed });
        } else {
            console.log("Checking password for existing user...");
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return res.status(400).json({ success: false, message: "Invalid password" });
            }
        }

        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET || 'SUPER_SECRET',
            { expiresIn: '24h' }
        );

        res.json({ success: true, token, email: user.email });

    } catch (err) {
        console.error("🔥 Auth Error Details:", err); // Ye Render logs mein dikhega
        res.status(500).json({ success: false, error: "Database or Server Error" });
    }
});

/* =======================
   STRIPE CHECKOUT (SECURE)
======================= */
app.post('/api/create-checkout-session', verifyToken, async (req, res) => {
    try {
        const { items, email } = req.body;

        const line_items = items.map(item => ({
            price_data: {
                currency: 'gbp',
                product_data: { name: item.name },
                unit_amount: Math.round(item.price * 100),
            },
            quantity: 1,
        }));

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items,
            mode: 'payment',
            customer_email: email,
            success_url: `${process.env.FRONTEND_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.FRONTEND_URL}/cancel.html`,
        });

        const totalAmount =
            line_items.reduce((sum, i) => sum + i.price_data.unit_amount, 0) / 100;

        await Order.create({
            items,
            total: `£${totalAmount.toFixed(2)}`,
            customerEmail: email,
            stripeSessionId: session.id
        });

        res.json({ url: session.url });

    } catch (err) {
        console.error("❌ Stripe Error:", err.message);
        res.status(500).json({ error: "Stripe checkout failed" });
    }
});

/* =======================
   CONTACT / INQUIRY
======================= */
app.post('/api/inquiry', async (req, res) => {
    try {
        const inquiry = await Inquiry.create(req.body);
        res.status(201).json({ success: true, inquiry });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

/* =======================
   SERVER START
======================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
    console.log(`🚀 Professional Server running on port ${PORT}`)
);
