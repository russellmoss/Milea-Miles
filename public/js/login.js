
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        try {
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password }),
            });

            const data = await response.json();

            if (response.ok) {
                // Store token along with other user details for use in future requests.
                localStorage.setItem('token', data.token);
                localStorage.setItem('userName', `${data.user.firstName} ${data.user.lastName}`);
                localStorage.setItem('loyaltyPoints', data.user.loyaltyPoints || 0);
                localStorage.setItem('userId', data.user.id);
                localStorage.setItem('userEmail', email);

                window.location.href = 'dashboard.html';
            } else {
                alert(data.message || 'Login failed. Please try again.');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred. Please try again later.');
        }
    });