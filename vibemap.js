/* ====== vibemap.js (merged and edited) ====== */
// 🔄 Reset accounts & sessions once (so we start fresh)
/*localStorage.removeItem('vibemapUsers');
localStorage.removeItem('currentVibeMapUser');*/

let currentUser = null;
let registeredUsers = JSON.parse(localStorage.getItem('vibemapUsers')) || [];

/* -------------------- Mouse particle + Tilt + Floating shapes -------------------- */
document.addEventListener("mousemove", function(e) {
  const particle = document.createElement("div");
  particle.className = "mouse-particle";
  particle.style.left = `${e.pageX}px`;
  particle.style.top = `${e.pageY}px`;
  document.body.appendChild(particle);
  setTimeout(() => {
    particle.remove();
  }, 800);
});

// Tilt / 3D effect on containers
document.querySelectorAll('.auth-box, .welcome-section').forEach((el) => {
  el.classList.add('tilt-container');
  el.addEventListener('mousemove', (e) => {
    const { width, height, left, top } = el.getBoundingClientRect();
    const x = e.clientX - left;
    const y = e.clientY - top;
    const rotateX = ((y / height) - 0.5) * 10;
    const rotateY = ((x / width) - 0.5) * -10;
    el.style.transform = `rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
  });
  el.addEventListener('mouseleave', () => {
    el.style.transform = `rotateX(0deg) rotateY(0deg)`;
  });
});

// Floating shapes in background
function createFloatingShapes() {
  const container = document.querySelector('.auth-container');
  if (!container) return;
  const shapes = ['circle', 'square', 'triangle'];
  for (let i = 0; i < 15; i++) {
    const shape = document.createElement('div');
    const type = shapes[Math.floor(Math.random() * shapes.length)];
    shape.className = `floating-shape ${type}`;
    shape.style.top = `${Math.random() * 100}%`;
    shape.style.left = `${Math.random() * 100}%`;
    const size = 5 + Math.random() * 10;
    shape.style.width = `${size}px`;
    shape.style.height = `${size}px`;
    shape.style.animationDuration = `${8 + Math.random() * 8}s`;
    container.appendChild(shape);
  }
}
window.addEventListener('DOMContentLoaded', createFloatingShapes);

/* -------------------- VibeXpert core -------------------- */

document.addEventListener('DOMContentLoaded', function () {
  initAnimatedBackground();
  setupEventListeners();
  applySavedTheme(); // <-- ADDED: Apply saved theme on load

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
    if (userGreet) userGreet.textContent = `Hi, ${currentUser.name}`;
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
  
  // ✅ EDITED: Changed ID to 'logoutBtn2' to match your HTML
  const logoutBtn = document.getElementById('logoutBtn2'); 
  
  const cameraBtn = document.getElementById('cameraBtn');

  if (cameraBtn) {
    cameraBtn.addEventListener('click', openCameraOrGallery);
  }

  if (loginForm) loginForm.addEventListener('submit', handleLogin);
  if (signupForm) signupForm.addEventListener('submit', handleSignup);
  if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

  document.querySelectorAll('.auth-tab').forEach(tab => {
    tab.addEventListener('click', function () {
      switchAuthTab(this.dataset.tab);
    });
  });

  document.querySelectorAll('.nav-item').forEach(link => {
    link.addEventListener('click', function(e) {
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

  setupSearchFunctionality();
  setupThemeSwitcher(); // <-- ADDED: Setup for the new theme buttons
}

/* -------------------- ✅ NEW: Dark/Light Mode Theme Switcher -------------------- */
function setupThemeSwitcher() {
    const darkModeToggle = document.getElementById('darkModeToggle');
    const themeOptions = document.querySelector('.theme-options');
    const setDarkModeBtn = document.getElementById('setDarkModeBtn');
    const setLightModeBtn = document.getElementById('setLightModeBtn');
    const body = document.body;

    if (!darkModeToggle || !themeOptions || !setDarkModeBtn || !setLightModeBtn) return;

    // Show/hide the theme options sub-menu
    darkModeToggle.addEventListener('click', (e) => {
        // Stop the click from closing the menu immediately
        e.stopPropagation(); 
        themeOptions.style.display = themeOptions.style.display === 'block' ? 'none' : 'block';
    });

    // Set theme to Dark
    setDarkModeBtn.addEventListener('click', () => {
        body.classList.remove('light-mode');
        body.classList.add('dark-mode');
        localStorage.setItem('vibeTheme', 'dark'); // Save preference
        themeOptions.style.display = 'none';
    });
    
    // Set theme to Light
    setLightModeBtn.addEventListener('click', () => {
        body.classList.remove('dark-mode');
        body.classList.add('light-mode');
        localStorage.setItem('vibeTheme', 'light'); // Save preference
        themeOptions.style.display = 'none';
    });

    // Hide theme options if clicking anywhere else
    document.addEventListener('click', () => {
        if (themeOptions.style.display === 'block') {
            themeOptions.style.display = 'none';
        }
    });
}

function applySavedTheme() {
    const savedTheme = localStorage.getItem('vibeTheme') || 'dark'; // Default to dark
    const body = document.body;
    if (savedTheme === 'light') {
        body.classList.remove('dark-mode');
        body.classList.add('light-mode');
    } else {
        body.classList.remove('light-mode');
        body.classList.add('dark-mode');
    }
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

/* Login */
function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;
  if (!username || !password) {
    showAlert('Please fill in all fields', 'error');
    return;
  }

  const user = registeredUsers.find(u =>
    (u.email && u.email.toLowerCase() === username.toLowerCase()) ||
    (u.regNumber && u.regNumber.toLowerCase() === username.toLowerCase())
  );

  if (user && user.password === password) {
    currentUser = user;
    localStorage.setItem('currentVibeMapUser', JSON.stringify(user));
    showAlert('Login successful!', 'success');
    setTimeout(showMainPage, 600);
  } else {
    showAlert('Invalid credentials', 'error');
  }
}

/* Signup */
function handleSignup(e) {
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
  if (registeredUsers.some(u => (u.email && u.email.toLowerCase() === email.toLowerCase()) || (u.regNumber && u.regNumber.toLowerCase() === regNumber.toLowerCase()))) {
    showAlert('User already exists', 'error');
    return;
  }

  const newUser = { name, email, regNumber, password, gender, userType, interests, hobbies, createdAt: new Date().toISOString() };
  registeredUsers.push(newUser);
  localStorage.setItem('vibemapUsers', JSON.stringify(registeredUsers));
  currentUser = newUser;
  localStorage.setItem('currentVibeMapUser', JSON.stringify(newUser));
  showAlert('Account created successfully!', 'success');
  
  showSignupPopup(newUser.name);
  setTimeout(showMainPage, 1500);
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

  searchBox.addEventListener('input', function(e) {
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

  document.addEventListener('click', function(event) {
    if (!searchBox.contains(event.target) && !searchResults.contains(event.target)) {
      searchResults.style.display = 'none';
    }
  });
}

/* -------------------- Animated background -------------------- */
function initAnimatedBackground() {
  const bg = document.getElementById('animatedBg');
  if (!bg) return;
  bg.innerHTML = ''; // Clear previous elements to avoid duplication

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
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    observer.observe(el);
  });
});

/* -------------------- Signup Popup -------------------- */
function showSignupPopup(username) {
  const popup = document.getElementById('signupPopup');
  const title = document.getElementById('popupTitle');
  const msg = document.getElementById('popupMessage');
  if (!popup) return;

  title.textContent = "🎉Sign In Successful🎉";
  msg.textContent = `Thank you ${username}, for signing up to VibeXpert. You Can Now Connect & Vibe.`;
  popup.style.display = 'flex';

  const duration = 2000;
  const end = Date.now() + duration;

  (function frame() {
    confetti({ particleCount: 5, angle: 60, spread: 55, origin: { x: 0 } });
    confetti({ particleCount: 5, angle: 120, spread: 55, origin: { x: 1 } });
    if (Date.now() < end) {
      requestAnimationFrame(frame);
    }
  })();

  setTimeout(() => {
    popup.style.display = 'none';
  }, 6000);
}

/* -------------------- Forgot Password -------------------- */
function handleForgotPassword(e) {
  e.preventDefault();
  const email = document.getElementById("forgotEmail").value.trim();
  if (!email) {
    showAlert("Please enter your email", "error");
    return;
  }
  
  // This is a demo. In a real app, you would fetch from a server.
  const userExists = registeredUsers.some(u => u.email === email);
  if (userExists) {
      showAlert("Reset code sent to your email! (Demo Code: 123456)", "success");
      window.sessionStorage.setItem("resetEmail", email);
      window.sessionStorage.setItem("resetCode", "123456"); // Demo code
      document.getElementById("resetCodeContainer").style.display = "block";
  } else {
      showAlert("Email not found in our records.", "error");
  }
}

function handleResetPassword() {
  const code = document.getElementById("resetCodeInput").value.trim();
  const newPassword = document.getElementById("newPassword").value.trim();
  const savedCode = window.sessionStorage.getItem("resetCode");
  const email = window.sessionStorage.getItem("resetEmail");

  if (code !== savedCode) {
    showAlert("Invalid reset code", "error");
    return;
  }

  const userIndex = registeredUsers.findIndex(u => u.email === email);
  if (userIndex >= 0) {
    registeredUsers[userIndex].password = newPassword;
    localStorage.setItem("vibemapUsers", JSON.stringify(registeredUsers));
    showAlert("Password reset successful! Please login.", "success");
    switchAuthTab("login");
  } else {
    showAlert("User not found", "error");
  }
}
/* -------------------- Camera & Post Upload -------------------- */
function openCameraOrGallery() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = 'image/*';
  input.capture = 'environment';
  input.onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const previewURL = URL.createObjectURL(file);
    showPostPreview(previewURL, 'VIT Bhopal University'); // Default location
  };
  input.click();
}

function showPostPreview(imageURL, suggestedLocation) {
  const modal = document.createElement('div');
  modal.className = 'post-preview-modal';
  modal.innerHTML = `
    <div class="post-preview-content">
      <img src="${imageURL}" style="max-width:100%; border-radius:10px;">
      <input type="text" id="locationInput" placeholder="Enter location" value="${suggestedLocation}">
      <div class="filters">
        <button onclick="applyFilter('none')">Normal</button>
        <button onclick="applyFilter('grayscale(100%)')">B/W</button>
        <button onclick="applyFilter('sepia(80%)')">Sepia</button>
        <button onclick="applyFilter('contrast(150%)')">Contrast+</button>
      </div>
      <button id="postBtn">Post</button>
      <button id="cancelBtn">Cancel</button>
    </div>
  `;
  document.body.appendChild(modal);

  document.getElementById('cancelBtn').addEventListener('click', () => modal.remove());
  document.getElementById('postBtn').addEventListener('click', () => {
    const loc = document.getElementById('locationInput').value;
    alert('Photo posted with location: ' + loc);
    modal.remove();
  });
}

function applyFilter(filter) {
  const img = document.querySelector('.post-preview-content img');
  if (img) img.style.filter = filter;
}

/* Attach forgot/reset handlers */
document.addEventListener("DOMContentLoaded", () => {
  const forgotForm = document.getElementById("forgotForm");
  if (forgotForm) forgotForm.addEventListener("submit", handleForgotPassword);

  const resetBtn = document.getElementById("resetPasswordBtn");
  if (resetBtn) resetBtn.addEventListener("click", handleResetPassword);
});

/* Post button logic (if you add a manual post section later) */
document.addEventListener("DOMContentLoaded", () => {
  const addPostBtn = document.getElementById("addPostBtn");
  if (!addPostBtn) return; // Exit if the button isn't on the page

  const postText = document.getElementById("postText");
  const postImage = document.getElementById("postImage");
  const userPosts = document.getElementById("userPosts");

  addPostBtn.addEventListener("click", () => {
    const text = postText.value.trim();
    const file = postImage.files[0];
    if (!text && !file) {
      alert("Please enter text or select an image to post!");
      return;
    }

    const post = document.createElement("div");
    post.classList.add("post");
    let contentHTML = `<p>${text}</p>`;
    if (file) {
      const imgURL = URL.createObjectURL(file);
      contentHTML += `<img src="${imgURL}" alt="Post Image" style="width:100%;border-radius:10px;margin-top:10px;">`;
    }
    post.innerHTML = `
      <div class="post-header">
        <div class="post-author">@you</div>
        <div class="post-time">just now</div>
      </div>
      ${contentHTML}
    `;
    userPosts.prepend(post);
    postText.value = "";
    postImage.value = "";
  });
});

/* Sidebar menu toggle */
document.addEventListener('DOMContentLoaded', () => {
    const menuBtn = document.querySelector('.menu-btn');
    const sidebar = document.querySelector('.sidebar');
    const closeBtn = document.querySelector('.close-sidebar');

    if (menuBtn && sidebar && closeBtn) {
        menuBtn.addEventListener('click', () => {
            sidebar.classList.add('active');
        });

        closeBtn.addEventListener('click', () => {
            sidebar.classList.remove('active');
        });
    }
});
// Create a glowing circle that follows the mouse with a pop effect
document.addEventListener('DOMContentLoaded', () => {
  const authBg = document.getElementById('animatedBg'); // Your background container

  if (!authBg) return;

  // Create glow element
  const glow = document.createElement('div');
  glow.style.position = 'fixed';
  glow.style.pointerEvents = 'none';
  glow.style.width = '150px';
  glow.style.height = '150px';
  glow.style.borderRadius = '50%';
  glow.style.background = 'radial-gradient(circle, rgba(79,116,163,0.5) 0%, transparent 70%)';
  glow.style.mixBlendMode = 'screen';
  glow.style.transition = 'transform 0.15s ease, opacity 0.3s ease';
  glow.style.transform = 'translate(-50%, -50%) scale(1)';
  glow.style.opacity = '0';
  glow.style.zIndex = '9999';

  document.body.appendChild(glow);

  document.addEventListener('mousemove', e => {
    glow.style.left = `${e.clientX}px`;
    glow.style.top = `${e.clientY}px`;
    glow.style.opacity = '5';
    // Animate pop according to speed (optional)
    glow.style.transform = 'translate(-50%, -50%) scale(1.2)';
    clearTimeout(glow._timeout);
    glow._timeout = setTimeout(() => {
      glow.style.transform = 'translate(-50%, -50%) scale(1)';
    }, 150);
  });

  document.addEventListener('mouseleave', () => {
    glow.style.opacity = '4';
  });
});
