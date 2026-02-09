/* ====== VibeXpert - Updated with Backend Integration ====== */

// 🔧 BACKEND API URL - Change this when you deploy
const API_URL = 'http://localhost:5000/api/auth';
// For production, change to: const API_URL = 'https://your-backend-url.onrender.com/api/auth';

let currentUser = null;

document.addEventListener('DOMContentLoaded', function () {
  initAnimatedBackground();
  setupEventListeners();

  // Show main page only if user logged in
  const savedUser = localStorage.getItem('currentVibeMapUser');
  if (savedUser) {
    currentUser = JSON.parse(savedUser);
    showMainPage();
  } else {
    showAuthPage();
  }
});

/* -------------------- Page show/hide -------------------- */
function showAuthPage() {
  const auth = document.getElementById('authPage');
  const main = document.getElementById('mainPage');
  if (auth) auth.style.display = 'flex';
  if (main) main.style.display = 'none';
  switchAuthTab('login');
}

function showMainPage() {
  const auth = document.getElementById('authPage');
  const main = document.getElementById('mainPage');
  if (auth) auth.style.display = 'none';
  if (main) main.style.display = 'block';
  if (currentUser) {
    const userGreet = document.querySelector('#userGreeting span');
    if (userGreet) userGreet.textContent = `Hi! ${currentUser.name}`;
  }
  switchPage('home');
}

/* -------------------- Auth handlers -------------------- */
function handleLogout(e) {
  e?.preventDefault();
  currentUser = null;
  localStorage.removeItem('currentVibeMapUser');
  showAuthPage();
  const loginForm = document.getElementById('loginForm');
  const signupForm = document.getElementById('signupForm');
  if (loginForm) loginForm.reset();
  if (signupForm) signupForm.reset();
}

function setupEventListeners() {
  const loginForm = document.getElementById('loginForm');
  const signupForm = document.getElementById('signupForm');
  const forgotForm = document.getElementById('forgotForm');
  const logoutBtn = document.getElementById('logoutBtn');

  if (loginForm) loginForm.addEventListener('submit', handleLogin);
  if (signupForm) signupForm.addEventListener('submit', handleSignup);
  if (forgotForm) forgotForm.addEventListener('submit', handleForgotPassword);
  if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

  document.querySelectorAll('.auth-tab').forEach(tab => {
    tab.addEventListener('click', function () {
      switchAuthTab(this.dataset.tab);
    });
  });

  document.querySelectorAll('.nav-item').forEach(link => {
    link.addEventListener('click', function (e) {
      e.preventDefault();
      document.querySelectorAll('.nav-item').forEach(l => l.classList.remove('active'));
      this.classList.add('active');
      switchPage(this.dataset.page);
    });
  });

  const logo = document.querySelector('.logo');
  if (logo) {
    logo.addEventListener('click', function () {
      switchPage('home');
      document.querySelectorAll('.nav-item').forEach(l => l.classList.remove('active'));
      const homeLink = document.querySelector('[data-page="home"]');
      if (homeLink) homeLink.classList.add('active');
    });
  }

  // Forgot password link
  const forgotLink = document.querySelector('.forgot-password a');
  if (forgotLink) {
    forgotLink.addEventListener('click', function (e) {
      e.preventDefault();
      switchAuthTab('forgot');
    });
  }

  setupSearchFunctionality();
}

/* Switch auth tabs */
function switchAuthTab(tabName) {
  document.querySelectorAll('.auth-tab').forEach(tab => tab.classList.remove('active'));
  const activeTab = document.querySelector(`[data-tab="${tabName}"]`);
  if (activeTab) activeTab.classList.add('active');

  document.querySelectorAll('.form-section').forEach(s => s.classList.remove('active'));
  const section = document.getElementById(`${tabName}-section`);
  if (section) section.classList.add('active');
  clearAlerts();
}

/* ==================== LOGIN (Backend Integration) ==================== */
async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;

  if (!username || !password) {
    showAlert('Please fill in all fields', 'error');
    return;
  }

  showAlert('Logging in...', 'success');

  try {
    const response = await fetch(`${API_URL}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (data.success) {
      currentUser = data.user;
      localStorage.setItem('currentVibeMapUser', JSON.stringify(data.user));
      showAlert('Login successful!', 'success');
      setTimeout(showMainPage, 600);
    } else {
      showAlert(data.message || 'Invalid credentials', 'error');
    }
  } catch (error) {
    console.error('Login error:', error);
    showAlert('Server error. Please try again.', 'error');
  }
}

/* ==================== SIGNUP (Backend Integration) ==================== */
async function handleSignup(e) {
  e.preventDefault();

  const name = document.getElementById('signupName').value.trim();
  const email = document.getElementById('signupEmail').value.trim();
  const regNumber = document.getElementById('signupRegNumber').value.trim();
  const password = document.getElementById('signupPassword').value;
  const confirmPassword = document.getElementById('signupConfirmPassword').value;
  const gender = document.querySelector('input[name="gender"]:checked')?.value || '';
  const userType = document.querySelector('input[name="usertype"]:checked')?.value || '';
  const interests = Array.from(document.querySelectorAll('input[name="interests"]:checked')).map(i => i.value);
  const hobbies = document.getElementById('signupHobbies')?.value.trim() || '';

  // Frontend validation
  if (!name || !email || !regNumber || !password || !confirmPassword || !gender || !userType) {
    showAlert('Please fill in all required fields', 'error');
    return;
  }
  if (!validateEmail(email)) {
    showAlert('Please enter a valid email address', 'error');
    return;
  }
  if (password.length < 6) {
    showAlert('Password must be at least 6 characters', 'error');
    return;
  }
  if (password !== confirmPassword) {
    showAlert('Passwords do not match', 'error');
    return;
  }

  showAlert('Creating your account...', 'success');

  try {
    const response = await fetch(`${API_URL}/signup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name,
        email,
        regNumber,
        password,
        gender,
        userType,
        interests,
        hobbies
      })
    });

    const data = await response.json();

    if (data.success) {
      showAlert('Account created! Check your email to verify.', 'success');
      showSignupPopup(name);

      // Auto-login after successful signup
      currentUser = data.user;
      localStorage.setItem('currentVibeMapUser', JSON.stringify(data.user));

      setTimeout(showMainPage, 2000);
    } else {
      showAlert(data.message || 'Signup failed', 'error');
    }
  } catch (error) {
    console.error('Signup error:', error);
    showAlert('Server error. Please try again.', 'error');
  }
}

/* ==================== FORGOT PASSWORD (Backend Integration) ==================== */
async function handleForgotPassword(e) {
  e.preventDefault();
  const email = document.getElementById('forgotEmail').value.trim();

  if (!email) {
    showAlert('Please enter your email', 'error');
    return;
  }

  if (!validateEmail(email)) {
    showAlert('Please enter a valid email address', 'error');
    return;
  }

  showAlert('Sending reset email...', 'success');

  try {
    const response = await fetch(`${API_URL}/forgot-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email })
    });

    const data = await response.json();

    if (data.success) {
      showAlert('Password reset email sent! Check your inbox.', 'success');
      setTimeout(() => {
        switchAuthTab('login');
      }, 3000);
    } else {
      showAlert(data.message || 'Failed to send reset email', 'error');
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    showAlert('Server error. Please try again.', 'error');
  }
}

/* Navigation between main pages */
function switchPage(pageId) {
  document.querySelectorAll('.content-section').forEach(sec => sec.classList.remove('active'));
  const target = document.getElementById(`${pageId}-content`);
  if (target) target.classList.add('active');
}

/* Alerts */
function showAlert(msg, type = 'success') {
  const c = document.getElementById('alertContainer');
  if (!c) return;
  c.innerHTML = `<div class="alert ${type}">${msg}</div>`;
  setTimeout(() => { if (c) c.innerHTML = ''; }, 3000);
}

function clearAlerts() {
  const c = document.getElementById('alertContainer');
  if (c) c.innerHTML = '';
}

/* Utils */
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

/* -------------------- Search (demo users) -------------------- */
function setupSearchFunctionality() {
  const users = [
    { name: 'Arjun K.', interest: 'Food Blogger' },
    { name: 'Priya S.', interest: 'Art Enthusiast' },
    { name: 'Rohit M.', interest: 'Tech Geek' },
    { name: 'Sneha R.', interest: 'Music Lover' },
    { name: 'Dev P.', interest: 'Sports Fan' },
    { name: 'Ananya T.', interest: 'Book Worm' },
    { name: 'Smi', interest: 'Web Developer' }
  ];

  const searchBox = document.getElementById('searchBox');
  const searchResults = document.getElementById('searchResults');
  if (!searchBox || !searchResults) return;

  searchBox.addEventListener('input', function (e) {
    const query = e.target.value.toLowerCase();
    searchResults.innerHTML = '';
    if (query.length > 1) {
      const filtered = users.filter(u => u.name.toLowerCase().includes(query) || u.interest.toLowerCase().includes(query));
      if (filtered.length) {
        filtered.forEach(u => {
          const div = document.createElement('div');
          div.className = 'search-result-item';
          div.textContent = `${u.name} - ${u.interest}`;
          div.addEventListener('click', () => {
            searchBox.value = u.name;
            searchResults.style.display = 'none';
          });
          searchResults.appendChild(div);
        });
        searchResults.style.display = 'block';
      } else {
        const no = document.createElement('div');
        no.className = 'search-result-item';
        no.textContent = 'No users found';
        no.style.color = '#666';
        searchResults.appendChild(no);
        searchResults.style.display = 'block';
      }
    } else {
      searchResults.style.display = 'none';
    }
  });

  document.addEventListener('click', function (event) {
    if (!searchBox.contains(event.target) && !searchResults.contains(event.target)) {
      searchResults.style.display = 'none';
    }
  });
}

/* -------------------- Animated background -------------------- */
function initAnimatedBackground() {
  const bg = document.getElementById('animatedBg');
  if (!bg) return;

  const dotColors = ['rgba(79,116,163,0.4)', 'rgba(141,164,211,0.35)', 'rgba(90,127,184,0.35)'];
  for (let i = 0; i < 30; i++) {
    const d = document.createElement('div');
    d.className = 'dot';
    d.style.left = Math.random() * 100 + '%';
    d.style.top = Math.random() * 100 + '%';
    d.style.animationDelay = Math.random() * 8 + 's';
    d.style.background = dotColors[Math.floor(Math.random() * dotColors.length)];
    bg.appendChild(d);
  }

  for (let i = 0; i < 15; i++) {
    const l = document.createElement('div');
    l.className = 'line';
    l.style.left = Math.random() * 100 + '%';
    l.style.top = Math.random() * 100 + '%';
    l.style.animationDelay = Math.random() * 10 + 's';
    l.style.transform = 'rotate(' + Math.random() * 360 + 'deg)';
    l.style.background = 'linear-gradient(90deg, transparent, rgba(79,116,163,0.18), transparent)';
    bg.appendChild(l);
  }
}

/* -------------------- Extras: interactions & scroll animations -------------------- */
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.canteen-card').forEach(card => {
    card.addEventListener('click', () => {
      const name = card.querySelector('h3')?.textContent || 'Canteen';
      showAlert(`${name} menu coming soon!`, 'success');
    });
  });

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'none';
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });

  const toObserve = document.querySelectorAll('.fade-in, .college-photo, .canteen-card, .post');
  toObserve.forEach(el => {
    el.style.opacity = el.style.opacity || '0';
    el.style.transform = el.style.transform || 'translateY(20px)';
    observer.observe(el);
  });
});

/* -------------------- COMMUNITY CHAT -------------------- */
let chatInterval = null;
let currentPinMessageId = null;

function setupChat() {
  const sendBtn = document.getElementById('sendMessageBtn');
  const chatInput = document.getElementById('chatInput');
  const pinModal = document.getElementById('pinModal');
  const closeModal = document.querySelector('.close-modal');
  const confirmPinBtn = document.getElementById('confirmPinBtn');

  if (sendBtn) {
    sendBtn.addEventListener('click', sendMessage);
  }

  if (chatInput) {
    chatInput.addEventListener('keypress', function (e) {
      if (e.key === 'Enter') sendMessage();
    });
  }

  if (closeModal) {
    closeModal.addEventListener('click', () => {
      pinModal.style.display = 'none';
    });
  }

  window.addEventListener('click', (e) => {
    if (e.target == pinModal) {
      pinModal.style.display = 'none';
    }
  });

  if (confirmPinBtn) {
    confirmPinBtn.addEventListener('click', confirmPinMessage);
  }

  // Poll for messages when on communities page
  setInterval(() => {
    const isCommunitiesActive = document.getElementById('communities-content').classList.contains('active');
    if (isCommunitiesActive) {
      loadMessages();
    }
  }, 5000); // 5 sec polling
}

async function loadMessages() {
  const container = document.getElementById('chatMessages');
  if (!container) return;

  try {
    const response = await fetch(`${API_URL.replace('/auth', '')}/messages`);
    const data = await response.json();

    if (data.success) {
      // Clear current messages? Or diff? For simplicity, we'll rebuild if changes detected or just rebuild.
      // Optimization: storing last message ID or timestamp could be better, but for MVP rebuild is safer.
      container.innerHTML = '';

      if (data.messages.length === 0) {
        container.innerHTML = '<div style="text-align:center; color:#888; margin-top:20px;">No active messages. Say hi! 👋</div>';
        return;
      }

      data.messages.forEach(msg => {
        const isOwn = currentUser && msg.user_id === currentUser.id;
        const msgDiv = document.createElement('div');
        msgDiv.className = `message-bubble ${isOwn ? 'own' : 'other'}`;

        let pinHtml = '';
        if (msg.is_pinned) {
          pinHtml = `<div class="pinned-badge">📌 Pinned</div>`;
        }

        // Pin button (allow everyone to pin for now as per "if we pin any chart")
        // In real app maybe only admin or owner. Here any user.
        const pinBtnHtml = `<button class="pin-btn ${msg.is_pinned ? 'active' : ''}" onclick="openPinModal('${msg.id}')" title="Pin Message">📌</button>`;

        const time = new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        msgDiv.innerHTML = `
          <div class="message-header">
            <span class="message-author">${msg.user_name || 'User'}</span>
            <span style="display:flex; align-items:center;">
              ${pinHtml}
              ${pinBtnHtml}
              <span class="message-time">${time}</span>
            </span>
          </div>
          <div class="message-content">${msg.content}</div>
        `;
        container.appendChild(msgDiv);
      });

      // Auto scroll to bottom only if near bottom or first load? 
      // For now, let's just scroll to bottom relative simple. 
      // container.scrollTop = container.scrollHeight; 
    }
  } catch (error) {
    console.error('Error loading messages:', error);
  }
}

async function sendMessage() {
  const input = document.getElementById('chatInput');
  const content = input.value.trim();

  if (!content) return;
  if (!currentUser) {
    showAlert('You must be logged in to chat!', 'error');
    return;
  }

  // Optimistic UI? No, wait for server response for reliability first.
  input.value = '';

  try {
    const response = await fetch(`${API_URL.replace('/auth', '')}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content,
        user_id: currentUser.id,
        user_name: currentUser.name || currentUser.username || 'User' // Handle mismatch
      })
    });

    const data = await response.json();
    if (data.success) {
      loadMessages(); // Refresh immediately
    } else {
      showAlert('Failed to send message', 'error');
    }
  } catch (error) {
    console.error('Send error:', error);
    showAlert('Error sending message', 'error');
  }
}

// Global scope for onclick
window.openPinModal = function (msgId) {
  currentPinMessageId = msgId;
  const modal = document.getElementById('pinModal');
  if (modal) modal.style.display = 'flex';
}

async function confirmPinMessage() {
  if (!currentPinMessageId) return;

  const durationInput = document.querySelector('input[name="pinDuration"]:checked');
  const duration = durationInput ? durationInput.value : 7;

  try {
    const response = await fetch(`${API_URL.replace('/auth', '')}/messages/${currentPinMessageId}/pin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        is_pinned: true,
        durationDays: duration
      })
    });

    const data = await response.json();
    if (data.success) {
      showAlert('Message pinned!', 'success');
      document.getElementById('pinModal').style.display = 'none';
      loadMessages();
    } else {
      showAlert('Failed to pin message', 'error');
    }
  } catch (error) {
    console.error('Pin error:', error);
    showAlert('Error pinning message', 'error');
  }
}

// Call setupChat when page loads
document.addEventListener('DOMContentLoaded', () => {
  setupChat();
});


/* -------------------- Signup Popup -------------------- */
function showSignupPopup(username) {
  const popup = document.getElementById('signupPopup');
  const title = document.getElementById('popupTitle');
  const msg = document.getElementById('popupMessage');
  if (!popup) return;

  title.textContent = "🎉 Congratulations!";
  msg.textContent = `Thank you ${username}, for signing up to VibeXpert. Check your email to verify your account!`;

  popup.style.display = 'flex';
}

document.addEventListener('DOMContentLoaded', () => {
  const closeBtn = document.getElementById('closePopup');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      document.getElementById('signupPopup').style.display = 'none';
    });
  }

});
