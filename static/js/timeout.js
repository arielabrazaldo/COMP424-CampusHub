// static/js/timeout.js

// Inactivity timeout setting (1800 seconds = 30 minutes)
const MAX_INACTIVITY_TIME = 1800000; // 30 minutes in milliseconds
let timeoutTimer;

// The URL for the server-side logout route.
const LOGOUT_URL = "/timeout_logout"; 

// Function to reset the timer on user activity
function resetTimer() {
    clearTimeout(timeoutTimer);
    // If the user is active, set the timer again
    timeoutTimer = setTimeout(logoutUser, MAX_INACTIVITY_TIME);
}

// Function to execute logout redirect
function logoutUser() {
    // Redirect to the new server-side logout route
    window.location.href = LOGOUT_URL;
}

// Initialize the timer when the page loads
resetTimer(); 

// Event listeners to detect user activity
document.addEventListener("mousemove", resetTimer);
document.addEventListener("keypress", resetTimer);
document.addEventListener("scroll", resetTimer);
document.addEventListener("click", resetTimer);