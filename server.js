const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Initialize Supabase Client with SERVICE ROLE KEY for admin operations
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Also create anon client for login
const supabaseAnon = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// Health Check Endpoints
app.get('/', (req, res) => {
  res.json({
    status: 'VibeXpert Server is running!',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'VibeXpert API' });
});

// ==================== SIGNUP ENDPOINT ====================
app.post('/api/auth/signup', async (req, res) => {
  try {
    const {
      name,
      email,
      regNumber,
      password,
      gender,
      userType,
      interests,
      hobbies
    } = req.body;

    // Validate required fields
    if (!name || !email || !regNumber || !password || !gender || !userType) {
      return res.status(400).json({
        success: false,
        message: 'All required fields must be filled'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Validate password length
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }

    // Create user with Supabase Admin API
    const { data: { user }, error: signUpError } = await supabase.auth.admin.createUser({
      email: email,
      password: password,
      user_metadata: {
        full_name: name,
        reg_number: regNumber,
        gender: gender,
        user_type: userType,
        interests: interests || [],
        hobbies: hobbies || ''
      },
      email_confirm: false // User must confirm email via Supabase
    });

    if (signUpError) {
      console.error('Supabase Auth Error:', signUpError);
      return res.status(400).json({
        success: false,
        message: signUpError.message || 'Signup failed'
      });
    }

    // Success response
    return res.status(201).json({
      success: true,
      message: 'Account created successfully! Check your email to confirm.',
      user: {
        id: user.id,
        email: user.email,
        name: name,
        regNumber: regNumber,
        gender: gender,
        userType: userType,
        interests: interests,
        hobbies: hobbies
      }
    });

  } catch (error) {
    console.error('Signup Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error during signup'
    });
  }
});

// ==================== LOGIN ENDPOINT ====================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Login with Supabase (using ANON key for user login)
    const { data: { user, session }, error: authError } = await supabaseAnon.auth.signInWithPassword({
      email: username,
      password: password
    });

    if (authError) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Get user metadata
    const userData = user.user_metadata || {};

    return res.status(200).json({
      success: true,
      message: 'Login successful!',
      user: {
        id: user.id,
        email: user.email,
        name: userData.full_name || 'User',
        regNumber: userData.reg_number,
        gender: userData.gender,
        userType: userData.user_type,
        interests: userData.interests || [],
        hobbies: userData.hobbies || ''
      },
      session: session
    });

  } catch (error) {
    console.error('Login Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
});

// ==================== FORGOT PASSWORD ENDPOINT ====================
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Send password reset email via Supabase
    const { error } = await supabaseAnon.auth.resetPasswordForEmail(email, {
      redirectTo: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password`
    });

    if (error) {
      console.error('Password Reset Error:', error);
      return res.status(400).json({
        success: false,
        message: 'Failed to send reset email'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Password reset email sent! Check your inbox.'
    });

  } catch (error) {
    console.error('Forgot Password Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ==================== RESET PASSWORD ENDPOINT ====================
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Token and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }

    // Update password using Supabase
    const { error } = await supabaseAnon.auth.updateUser({
      password: newPassword
    });

    if (error) {
      console.error('Reset Password Error:', error);
      return res.status(400).json({
        success: false,
        message: 'Failed to reset password'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Password reset successful! You can now login with your new password.'
    });

  } catch (error) {
    console.error('Reset Password Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ==================== COMMUNITY CHAT ENDPOINTS ====================

// 1. Get Messages (active only)
app.get('/api/messages', async (req, res) => {
  try {
    const { data: messages, error } = await supabase
      .from('messages')
      .select('*')
      .order('created_at', { ascending: true }); // We want oldest first to render top-down, or newest first if bottom-up. Usually chat is oldest at top.

    if (error) throw error;

    const now = new Date();
    const fiveDaysAgo = new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000);

    // Filter messages:
    // 1. Standard messages: created within last 5 days AND not pinned
    // 2. Pinned messages: pinned_expires_at > now
    const activeMessages = messages.filter(msg => {
      if (msg.is_pinned) {
        return msg.pinned_expires_at ? new Date(msg.pinned_expires_at) > now : true; // If no expiry set, treat as permanent (or handle otherwise)
      } else {
        return new Date(msg.created_at) > fiveDaysAgo;
      }
    });

    res.json({ success: true, messages: activeMessages });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch messages' });
  }
});

// 2. Send Message
app.post('/api/messages', async (req, res) => {
  try {
    const { content, user_id, user_name } = req.body;
    if (!content || !user_id) {
      return res.status(400).json({ success: false, message: 'Missing fields' });
    }

    const { data, error } = await supabase
      .from('messages')
      .insert([{ content, user_id, user_name, is_pinned: false }])
      .select();

    if (error) throw error;

    res.json({ success: true, message: data[0] });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});

// 3. Pin Message
app.post('/api/messages/:id/pin', async (req, res) => {
  try {
    const { id } = req.params;
    const { is_pinned, durationDays } = req.body; // durationDays needed if pinning

    let updateData = { is_pinned };

    if (is_pinned) {
      if (durationDays) {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + parseInt(durationDays));
        updateData.pinned_expires_at = expiresAt.toISOString();
      } else {
        // Default to maybe 365 days if not specified? Or require it. 
        // Let's assume infinite if null, but user logic wants "user given time".
        updateData.pinned_expires_at = null;
      }
    } else {
      updateData.pinned_expires_at = null;
    }

    const { data, error } = await supabase
      .from('messages')
      .update(updateData)
      .eq('id', id)
      .select();

    if (error) throw error;

    res.json({ success: true, message: data[0] });
  } catch (error) {
    console.error('Error pinning message:', error);
    res.status(500).json({ success: false, message: 'Failed to update pin status' });
  }
});

// ==================== LOGOUT ENDPOINT ====================
app.post('/api/auth/logout', async (req, res) => {
  try {
    const { error } = await supabaseAnon.auth.signOut();

    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Logout failed'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    console.error('Logout Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`✅ VibeXpert Server running on port ${PORT}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/health`);
});
