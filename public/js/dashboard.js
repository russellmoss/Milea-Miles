const userEmail = localStorage.getItem('userEmail');
const safeEmail = userEmail.replace(/[^a-zA-Z0-9]/g, '_');
const loyaltyCookieKey = `loyaltyPoints_${safeEmail}`;
const referralsCookieKey = `referrals_${safeEmail}`;

function isTokenExpired(token) {
    if (!token) return true;
    const payload = JSON.parse(atob(token.split(".")[1]));
    return Date.now() >= payload.exp * 1000;
}

function checkAuth() {
    const token = localStorage.getItem("token");
    if (!token || isTokenExpired(token)) {
        console.warn("Token expired or missing. Redirecting to login...");
        localStorage.removeItem("token");
        window.location.href = "index.html";
    }
}

checkAuth();

// Add Instagram database download button (admin-only)
if (localStorage.getItem('userEmail') === 'lance@fillintheblank.co') {
  document.addEventListener('DOMContentLoaded', function() {
    // Create download button
    const downloadButton = document.createElement('button');
    downloadButton.textContent = 'Download Instagram Database';
    downloadButton.style.position = 'fixed';
    downloadButton.style.top = '10px';
    downloadButton.style.right = '10px';
    downloadButton.style.backgroundColor = '#715100';
    downloadButton.style.color = '#fff';
    downloadButton.style.border = 'none';
    downloadButton.style.borderRadius = '5px';
    downloadButton.style.padding = '10px 15px';
    downloadButton.style.cursor = 'pointer';
    downloadButton.style.zIndex = '1000';
    
    // Create status popup
    const statusPopup = document.createElement('div');
    statusPopup.style.position = 'fixed';
    statusPopup.style.top = '60px';
    statusPopup.style.right = '10px';
    statusPopup.style.backgroundColor = 'white';
    statusPopup.style.border = '1px solid #ccc';
    statusPopup.style.borderRadius = '5px';
    statusPopup.style.padding = '15px';
    statusPopup.style.width = '300px';
    statusPopup.style.boxShadow = '0 2px 10px rgba(0,0,0,0.1)';
    statusPopup.style.display = 'none';
    statusPopup.style.zIndex = '1001';
    document.body.appendChild(statusPopup);
    
    // Function to check status before download
    function checkStatus() {
      const token = localStorage.getItem('token');
      statusPopup.style.display = 'block';
      statusPopup.innerHTML = '<p>Checking database status...</p>';
      
      fetch('/api/instagram-database-status', {
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json'
        }
      })
      .then(response => {
        if (!response.ok) throw new Error('Status check failed');
        return response.json();
      })
      .then(data => {
        let html = `
          <div style="position:relative;">
            <span style="position:absolute;top:0;right:0;cursor:pointer;font-weight:bold;padding:5px;" onclick="this.parentNode.parentNode.style.display='none'">✕</span>
            <h3 style="margin-top:0;margin-bottom:10px;">Instagram Database Status</h3>
            <p><strong>Handles in database:</strong> ${data.databaseSize}</p>
            <p><strong>Last updated:</strong> ${data.lastUpdated ? new Date(data.lastUpdated).toLocaleString() : 'Never'}</p>
            <p><strong>Currently building:</strong> ${data.isDatabaseBuilding ? 'Yes' : 'No'}</p>
            <p><strong>Status:</strong> ${data.buildStatus.currentProgress}</p>
        `;
        
        if (data.isDatabaseBuilding) {
          html += `<p style="color:#ff6600;font-weight:bold;">Database is currently building...</p>
                  <button id="checkAgainBtn" style="margin-right:10px;">Check Again</button>`;
        } else if (data.databaseSize > 0) {
          html += `<button id="downloadNowBtn" style="background-color:#715100;color:white;border:none;padding:8px 15px;border-radius:4px;cursor:pointer;">Download Now</button>`;
        } else {
          html += `<p style="color:red;">No data available yet.</p>`;
        }
        
        html += `</div>`;
        statusPopup.innerHTML = html;
        
        // Add event listeners for buttons
        const checkAgainBtn = document.getElementById('checkAgainBtn');
        if (checkAgainBtn) {
          checkAgainBtn.addEventListener('click', checkStatus);
        }
        
        const downloadNowBtn = document.getElementById('downloadNowBtn');
        if (downloadNowBtn) {
          downloadNowBtn.addEventListener('click', downloadDatabase);
        }
        
        // Auto-refresh if building
        if (data.isDatabaseBuilding) {
          setTimeout(checkStatus, 10000); // Check again in 10 seconds
        }
      })
      .catch(error => {
        statusPopup.innerHTML = `<p style="color:red;">Error checking status: ${error.message}</p>
                                <button id="closeErrorBtn">Close</button>`;
        document.getElementById('closeErrorBtn').addEventListener('click', () => {
          statusPopup.style.display = 'none';
        });
      });
    }
    
    // Function to download the database
    function downloadDatabase() {
      const token = localStorage.getItem('token');
      fetch('/api/get-instagram-database', {
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json'
        }
      })
      .then(response => {
        if (!response.ok) throw new Error('Download failed');
        return response.blob();
      })
      .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = 'instagram_handle_database.json';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        // Show success message
        const currentContent = statusPopup.innerHTML;
        statusPopup.innerHTML = currentContent + '<p style="color:green;margin-top:10px;">Download started!</p>';
      })
      .catch(error => {
        console.error('Error downloading database:', error);
        statusPopup.innerHTML += `<p style="color:red;">Download failed: ${error.message}</p>`;
      });
    }
    
    // Add click handler to check status first
    downloadButton.addEventListener('click', checkStatus);
    
    // Add to document
    document.body.appendChild(downloadButton);
  });
}

document.addEventListener("DOMContentLoaded", function () {

 var redeemedCount = 0;

var gotSome = false;
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

      data.referrals.reverse().forEach(referral => {
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
            gotSome = true;
            document.cookie = loyaltyCookieKey + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
            document.cookie = referralsCookieKey + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
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

  setTimeout( function () {
    if ( gotSome ) document.cookie = loyaltyCookieKey + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    //document.cookie = referralsCookieKey + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    updateLoyaltyPoints();
  }, redeemedCount * 400);


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

  document.cookie = loyaltyCookieKey + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
  document.cookie = referralsCookieKey + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";


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
      setTimeout(function() {location.reload(); }, 3000);
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
window.addEventListener('load', function() {
  const height = document.body.scrollHeight;
  window.parent.postMessage({ iframeHeight: height }, "*");

  setTimeout(function() {
    document.getElementById('refreshBtn').style.display = 'block';
  }, 3500);
});
document.getElementById('refreshBtn').addEventListener('click', function() {
  document.cookie = loyaltyCookieKey + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
  location.reload();
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
