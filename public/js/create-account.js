    // Toggle password visibility function.
    function togglePasswordVisibility(fieldId) {
      const field = document.getElementById(fieldId);
      field.type = field.type === 'password' ? 'text' : 'password';
    }

// Attach event listener instead of inline `onclick`
document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("togglePassword").addEventListener("click", () => togglePasswordVisibility("password"));
    document.getElementById("toggleConfirmPassword").addEventListener("click", () => togglePasswordVisibility("confirmPassword"));
});


    document.getElementById('createAccountForm').addEventListener('submit', async (e) => {
      e.preventDefault();

      // Retrieve form values.
      const firstName = document.getElementById('firstName').value.trim();
      const lastName = document.getElementById('lastName').value.trim();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value.trim();
      const confirmPassword = document.getElementById('confirmPassword').value.trim();
      const subscribe = document.getElementById('subscribe').checked;
      const messageElem = document.getElementById('message');

      // Simple client-side validation.
      if (password !== confirmPassword) {
        messageElem.innerText = 'Passwords do not match.';
        messageElem.style.color = 'red';
        return;
      }

      // IMPORTANT: Since the new server.js locks down /create-account,
      // we must include a valid JWT token in the request header.
      // For example, the token can be stored in localStorage after a prior login.
      const token = localStorage.getItem('token');
      /*if (!token) {
        messageElem.innerText = 'You are not authorized to create an account. Please log in first or use a valid invitation token.';
        messageElem.style.color = 'red';
        return;
      }*/

      const payload = {
        firstName,
        lastName,
        email,
        password,
        emailMarketingStatus: subscribe ? "Subscribed" : "Unsubscribed",
        metaData: { ambassador: "ambassador" }
      };



      const apiBase = window.location.origin;

      try {
        const response = await fetch(`${apiBase}/create-account`, {
          method: 'POST',
          headers: {
            ...{'Content-Type': 'application/json'}
          },
          body: JSON.stringify(payload),
        });


        if (response.ok) {
          const responseData = await response.json(); // Parse the response
          console.log("✅ Account Created:", responseData); // Log the full response
          messageElem.innerText = 'Account created successfully! Redirecting to login page...';
          messageElem.style.color = 'green';
          /*setTimeout(() => {
            window.location.href = './index.html';
          }, 3000);*/
        } else {
          const errorData = await response.json();
          messageElem.innerText = `Error: ${errorData.message}`;
          messageElem.style.color = 'red';
        }
      } catch (error) {
        messageElem.innerText = 'An unexpected error occurred. Please try again.';
        messageElem.style.color = 'red';
        console.error(error);
      }
    });