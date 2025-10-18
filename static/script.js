const container = document.querySelector('.container');
const signUpLink = document.querySelector('.SignUpLink');
const signInLink = document.querySelector('.SignInLink');

// --- Form Switching Logic ---
if (signUpLink) {
    signUpLink.addEventListener('click', (e) => {
        e.preventDefault();
        container.classList.add('active');
    });
}

if (signInLink) {
    signInLink.addEventListener('click', (e) => {
        e.preventDefault();
        container.classList.remove('active');
    });
}

// --- Admin Toggle Logic ---
const adminToggle = document.getElementById('adminToggle');
const adminCodeBox = document.getElementById('adminCodeBox');

if (adminToggle && adminCodeBox) {
    adminToggle.addEventListener('change', () => {
        if (adminToggle.checked) {
            adminCodeBox.style.display = 'block';
        } else {
            adminCodeBox.style.display = 'none';
        }
    });
}

