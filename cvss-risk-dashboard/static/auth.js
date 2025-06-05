document.addEventListener('DOMContentLoaded', function() {
    const signinForm = document.getElementById('signinForm');
    const signupForm = document.getElementById('signupForm');

    if (signinForm) {
        signinForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('signinUsername').value;
            const password = document.getElementById('signinPassword').value;
            
            try {
                const response = await fetch('/api/signin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await response.json();
                if (response.ok) {
                    localStorage.setItem('currentUser', JSON.stringify({ username: data.username, user_id: data.user_id }));
                    showMessage('Login successful! Redirecting...', 'success');
                    // Redirect to dashboard or a previously intended page
                    const returnUrl = new URLSearchParams(window.location.search).get('returnUrl');
                    window.location.href = returnUrl || 'dashboard.html'; 
                } else {
                    showMessage(data.error || 'Login failed', 'error');
                }
            } catch (error) {
                showMessage('Network error. Please try again.', 'error');
            }
        });
    }

    if (signupForm) {
        signupForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('signupUsername').value;
            const email = document.getElementById('signupEmail').value;
            const password = document.getElementById('signupPassword').value;
            
            try {
                const response = await fetch('/api/signup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, email, password })
                });
                const data = await response.json();
                if (response.ok) {
                    showMessage('Account created successfully! Please sign in.', 'success');
                    signupForm.reset();
                } else {
                    showMessage(data.error || 'Registration failed', 'error');
                }
            } catch (error) {
                showMessage('Network error. Please try again.', 'error');
            }
        });
    }
});

function showMessage(message, type) {
    const errorDiv = document.getElementById('errorMessage');
    const successDiv = document.getElementById('successMessage');
    
    // Ensure these elements exist on the page (e.g., login.html)
    if (!errorDiv || !successDiv) {
        console.warn('Notification elements (errorMessage, successMessage) not found on this page.');
        alert(`${type.toUpperCase()}: ${message}`); // Fallback to alert if divs are not present
        return;
    }

    errorDiv.style.display = 'none';
    successDiv.style.display = 'none';
    
    if (type === 'error') {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
    } else {
        successDiv.textContent = message;
        successDiv.style.display = 'block';
    }
    
    setTimeout(() => {
        errorDiv.style.display = 'none';
        successDiv.style.display = 'none';
    }, 5000);
} 