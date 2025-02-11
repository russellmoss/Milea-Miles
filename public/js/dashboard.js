document.addEventListener("DOMContentLoaded", function () {

 var redeemedCount = 0;
  // Retrieve stored token; if missing, redirect to login.
  const token = localStorage.getItem('token');
  if (!token) {
    console.error("No token found. Redirecting to login.");
    window.location.href = 'index.html';
    return;
  }

  // Helper function to return Authorization headers
  function getAuthHeaders() {
    return {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json'
    };
  }

  // Set welcome text.
  const ambassadorName = localStorage.getItem('userName') || 'Ambassador';
  document.getElementById('welcomeText').innerText = `Welcome, ${ambassadorName.split(' ')[0]}!`;

  // Handle referral form submission.
  const referralForm = document.getElementById('referralForm');
  referralForm.addEventListener('submit', (event) => handleReferralSubmit(event, ambassadorName));

  // Retrieve the user email from localStorage.
  const userEmail = localStorage.getItem('userEmail');
  if (!userEmail) {
    console.error('No userEmail found in localStorage.');
    return;
  }

  // Fetch and display referrals.
  fetch('/api/referrals?email=' + encodeURIComponent(userEmail), {
    headers: getAuthHeaders()
  })
    .then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    })
    .then(data => {
      const customerList = document.getElementById('customerList');

      data.referrals.forEach(referral => {
        const [email, metaRedeemed, promotionRedeemed] = referral;
        const li = document.createElement('li');

        li.innerHTML = `<span>${email}</span>
          <span data-email="${email}" data-meta-redeemed="${metaRedeemed}" data-promotion-redeemed="${promotionRedeemed}" class="redeemed ${promotionRedeemed}"></span>`;

        customerList.appendChild(li);
      });

      // Now, check for referrals that qualify for loyalty points.
 const redeemedSpans = document.querySelectorAll(".redeemed");
redeemedSpans.forEach((span, index) => { redeemedCount++;
  setTimeout(() => {
    const referreeEmail = span.getAttribute("data-email");
    const metaRedeemed = span.getAttribute("data-meta-redeemed") === "true";
    const promotionRedeemed = span.getAttribute("data-promotion-redeemed") === "true";
    //console.log(`Meta redeemed: ${metaRedeemed}, Promotion redeemed: ${promotionRedeemed}`);
    if (promotionRedeemed && !metaRedeemed) {
      // Send a request to update loyalty points.
      fetch('/api/update-loyalty', {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ referrerEmail: userEmail, referreeEmail: referreeEmail }),
      })
        .then(response => response.json())
        .then(result => {
          if (result.success) {
            console.log(`Loyalty points updated for ${userEmail}`);
            // After backend confirms update, change the UI state.
            span.setAttribute("data-meta-redeemed", "true");
            // Refresh displayed loyalty points.
            updateLoyaltyPoints();
          } else {
            console.error(`Failed to update loyalty points: ${result.error}`);
          }
        })
        .catch(error => console.error("Error updating loyalty points:", error));
    }
  }, index * 250); // Delay each update by 2 seconds * index
});

    })
    .catch(error => {
      console.error('Error fetching referrals:', error);
    });

  setTimeout( updateLoyaltyPoints, redeemedCount * 255);

  // Handle Instagram form submission.
  const instagramForm = document.getElementById('instagramForm');
  instagramForm.addEventListener('submit', function (e) {
    e.preventDefault();

    const instagramHandle = document.getElementById('instagramProfile').value.trim();
    if (!instagramHandle) {
      console.error("Please enter an Instagram profile.");
      return;
    }

    const payload = {
      userEmail: userEmail,
      instagramHandle: instagramHandle
    };

    fetch('/api/update-instagram', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload)
    })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          console.log('Instagram handle updated successfully.');
          document.getElementById('instagramForm').insertAdjacentHTML('afterend', '<p>Instagram handle updated!</p>');
        } else {
          console.error('Failed to update instagram handle:', data.error);
        }
      })
      .catch(error => console.error('Error updating instagram handle:', error));
  });

  // Fetch the current Instagram handle.
  fetch('/api/get-instagram?email=' + encodeURIComponent(userEmail), {
    headers: getAuthHeaders()
  })
    .then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    })
    .then(data => {
      const instagramInput = document.getElementById('instagramProfile');
      if (instagramInput) {
        instagramInput.value = data.instagramHandle || "";
        if (data.instagramHandle) {
          document.querySelector('.the-instagram').classList.add('filled');
          instagramForm.querySelector('input[type="text"]').disabled = true;
        }
      }
    })
    .catch(error => {
      console.error('Error fetching instagram handle:', error);
    });

  // Handle contact form submission.
  document.getElementById("contactForm").addEventListener("submit", function(event) {
    event.preventDefault();

    const message = document.getElementById("question").value.trim();
    fetch("/api/submit-contact-form", {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ email: userEmail, message: message })
    })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          alert("Form submitted successfully!");
        } else {
          alert("Error submitting form.");
        }
      })
      .catch(error => console.error("Error:", error));
  });
});

// Update loyalty points function.
function updateLoyaltyPoints() {
  console.log('Updating loyalty points...');
  const userEmail = localStorage.getItem('userEmail');
  const token = localStorage.getItem('token');
  fetch('/api/loyalty-points?email=' + encodeURIComponent(userEmail), {
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json'
    }
  })
    .then(response => response.json())
    .then(data => {
      //console.log("Loyalty Points Response:", data);
      const loyaltyPointsSpan = document.getElementById('loyaltyPoints');
      if (loyaltyPointsSpan) {
        loyaltyPointsSpan.textContent = data.points || 0;
      }
    })
    .catch(error => console.error('Error fetching loyalty points:', error));
}

// Handle referral submission.
async function handleReferralSubmit(event, ambassadorName) {
  event.preventDefault();

  const firstName = document.getElementById('refFirstName').value.trim();
  const lastName = document.getElementById('refLastName').value.trim();
  const email = document.getElementById('refEmail').value.trim();

  if (!firstName || !lastName || !email) {
    document.getElementById('referralStatus').innerText = 'Error: All fields are required.';
    document.getElementById('referralStatus').classList.add('error');
    return;
  }

  const payload = {
    referrerId: localStorage.getItem('userId'),
    referrerEmail: localStorage.getItem('userEmail'),
    referrerName: ambassadorName,
    firstName: firstName,
    lastName: lastName,
    email: email,
  };

  try {
    const response = await fetch('/referral', {
      method: 'POST',
      headers: {
        ...{'Content-Type': 'application/json'},
        ...{'Authorization': 'Bearer ' + localStorage.getItem('token')}
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (response.ok) {
      document.getElementById('referralStatus').innerText = 'Referral sent successfully!';
      document.getElementById('referralStatus').classList.add('success');
    } else {
      document.getElementById('referralStatus').innerText = `Error: ${data.message || 'An error occurred.'}`;
      document.getElementById('referralStatus').classList.add('error');
      console.error('API Error:', data);
    }
    setTimeout(() => {
      const referralStatus = document.getElementById('referralStatus');
      referralStatus.innerText = '';
      referralStatus.classList.remove('success', 'error');
    }, 5000);
  } catch (error) {
    document.getElementById('referralStatus').innerText = 'An error occurred. Please try again.';
    document.getElementById('referralStatus').classList.add('error');
    console.error('Network Error:', error);
  }
}
document.addEventListener("DOMContentLoaded", function () {
  const logoutButton = document.getElementById('logoutButton');
  if (logoutButton) {
    logoutButton.addEventListener('click', logout);
  }
});


function logout() {
  // Remove authentication-related data from localStorage.
  localStorage.removeItem('token');
  localStorage.removeItem('userName');
  localStorage.removeItem('userEmail');
  localStorage.removeItem('userId');

  // Optionally, remove other stored values (like loyaltyPoints) if needed.
  localStorage.removeItem('loyaltyPoints');

  // Redirect to the login page.
  window.location.href = '/';
}
