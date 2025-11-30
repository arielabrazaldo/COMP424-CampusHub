# COMP424-CampusHub

CampusHub is a simple, secure web application that acts as a personal notes platform for students, similar to a “mini Google Keep,” but built to demonstrate secure authentication and session management.

Imagine CampusHub as a small online notebook app hosted by your university. Instead of creating yet another username and password, students log in using their existing Google accounts. Once logged in, they can securely create and manage notes for their classes.

But behind the scenes, CampusHub is carefully engineered to enforce every major web security control a modern app should have.

The app allows users to:

Log in securely using Google OAuth 2.0 (OpenID Connect) — no passwords stored locally.

Create, read, update, and delete their own notes.

View only their own data — not others’ (prevents unauthorized access).

Log out and have their session properly invalidated.

Interact with a web API that enforces modern web security practices.

1. Login with Google
User clicks “Login with Google”.

The app redirects them to Google’s login page using the OAuth 2.0 Authorization Code Flow.

After successful authentication, Google sends the app a temporary authorization code.

The app exchanges that code for an ID token (contains verified user identity).

The app validates the token, creates a secure session, and stores minimal user data in it

2. Session & Cookie Handling
The app issues a session cookie like:

Set-Cookie: campushub.sid=<session-token>; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1800
This cookie is:

HttpOnly: Not accessible to JavaScript (prevents XSS theft).

Secure: Only sent over HTTPS.

SameSite=Lax: Protects against CSRF (Cross-Site Request Forgery).

Short-lived (30 min) and refreshed on activity.

3. Creating and Managing Notes
Authenticated users can:

GET /api/notes → view their own notes

POST /api/notes → create a new note

PUT /api/notes/{id} → update a note (owner only)

DELETE /api/notes/{id} → delete a note (owner only)

Each note is stored with an owner ID linked to the user’s Google identity.

This enforces authorization and ownership checks — you can’t view or edit another person’s notes.

4. CSRF (Cross-Site Request Forgery) Protection
All write actions (POST, PUT, DELETE) require a CSRF token.

The app issues a token via GET /csrf.

The frontend includes this token in headers (x-csrf-token) with every modifying request.

Without it, the server rejects the request with 403 Invalid CSRF token.

5. Logout and Session Destruction
When the user clicks “Logout,” the server:

Deletes the session from memory.

Sends an expired cookie to the browser.

After logout, protected endpoints like /api/notes or /me will return 401 Unauthorized.

Technical Design Highlights
Layer	Security Mechanism
Authentication	OAuth 2.0 / OIDC via Google
Session Management	Secure cookies, rotation, timeout
Authorization	Owner-based access checks
CSRF Defense	Token-based verification
Transport Security	HTTPS (self-signed for dev)
Headers	CSP, no framing, rate limiting
Data Validation	Input length limits, sanitization
Logging	Track login/logout and CRUD actions
 

Example Use Case Scenario
Alice logs into CampusHub with her Google account.

She creates three notes for her “Network Security” class.

Bob logs in separately — he can only see his own notes.

Alice leaves the page open for 35 minutes → her session expires automatically.

When she tries to add a note without a new CSRF token → request fails (403 Invalid CSRF token).
She logs out and back in → session and token are renewed.