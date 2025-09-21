;; Title: BitPass Identity Protocol
;; Summary: Bitcoin-native decentralized identity and authentication system
;; Description: A comprehensive identity management protocol built on Stacks
;;              that enables secure, self-sovereign digital identity creation
;;              and verification. Users can register unique identities, manage
;;              profile data, and authenticate across Bitcoin-powered applications
;;              while maintaining full control over their personal information.
;;              The protocol leverages Bitcoin's security model through Stacks
;;              to provide tamper-proof identity records and seamless cross-app
;;              authentication without centralized authorities.

;; ERROR CONSTANTS

(define-constant ERR-USER-EXISTS (err "User already exists"))
(define-constant ERR-USER-NOT-FOUND (err "User not found"))
(define-constant ERR-INVALID-USERNAME (err "Invalid username: must be between 3 and 50 characters"))
(define-constant ERR-INVALID-EMAIL (err "Invalid email: must be between 5 and 100 characters and contain '@' and '.'"))
(define-constant ERR-INVALID-IMAGE-URL (err "Invalid image URL: must be a valid URL string"))
(define-constant ERR-USERNAME-TAKEN (err "Username is already taken"))

;; DATA STRUCTURES

;; Main user registry mapping principals to their identity data
(define-map users principal
  {
    username: (string-ascii 50),
    email: (string-ascii 100),
    profile-image: (optional (string-utf8 256))
  }
)

;; Username availability tracking to prevent duplicates
(define-map taken-usernames (string-ascii 50) bool)

;; Global counter for total registered users
(define-data-var user-count uint u0)

;; PRIVATE VALIDATION FUNCTIONS

;; Validates username length requirements (3-50 characters)
(define-private (validate-username (username (string-ascii 50)))
  (let
    (
      (length (len username))
    )
    (and (>= length u3) (<= length u50))
  )
)

;; Validates email format and length requirements (5-100 characters, must contain @ and .)
(define-private (validate-email (email (string-ascii 100)))
  (let
    (
      (length (len email))
      (has-at (is-some (index-of email "@")))
      (has-dot (is-some (index-of email ".")))
    )
    (and (>= length u5) (<= length u100) has-at has-dot)
  )
)

;; Helper function for username matching during updates
(define-private (check-username-match (username (string-ascii 50)) (user principal) (found bool))
  (if found
    found
    (let ((user-info (unwrap-panic (map-get? users user))))
      (is-eq (get username user-info) username)
    )
  )
)

;; PUBLIC FUNCTIONS - IDENTITY MANAGEMENT

;; Registers a new user identity with username and email
;; @param username: Unique identifier (3-50 characters)
;; @param email: User's email address (5-100 characters, must contain @ and .)
;; @returns: (ok true) on success, error on failure
(define-public (register-user (username (string-ascii 50)) (email (string-ascii 100)))
  (let
    (
      (caller tx-sender)
      (safe-username (as-max-len? username u50))
      (safe-email (as-max-len? email u100))
    )
    ;; Validation checks
    (asserts! (is-none (map-get? users caller)) ERR-USER-EXISTS)
    (asserts! (is-some safe-username) ERR-INVALID-USERNAME)
    (asserts! (is-some safe-email) ERR-INVALID-EMAIL)
    (asserts! (validate-username (unwrap-panic safe-username)) ERR-INVALID-USERNAME)
    (asserts! (validate-email (unwrap-panic safe-email)) ERR-INVALID-EMAIL)
    (asserts! (is-none (map-get? taken-usernames (unwrap-panic safe-username))) ERR-USERNAME-TAKEN)

    ;; Create user record
    (map-set users caller
      {
        username: (unwrap-panic safe-username),
        email: (unwrap-panic safe-email),
        profile-image: none
      }
    )
    
    ;; Mark username as taken and increment counter
    (map-set taken-usernames (unwrap-panic safe-username) true)
    (var-set user-count (+ (var-get user-count) u1))
    (ok true)
  )
)

;; Updates an existing user's profile information
;; @param new-username: New username (3-50 characters)
;; @param new-email: New email address (5-100 characters)
;; @returns: (ok true) on success, error on failure
(define-public (update-profile (new-username (string-ascii 50)) (new-email (string-ascii 100)))
  (let
    (
      (caller tx-sender)
      (safe-username (as-max-len? new-username u50))
      (safe-email (as-max-len? new-email u100))
      (current-user (map-get? users caller))
    )
    ;; Validation checks
    (asserts! (is-some current-user) ERR-USER-NOT-FOUND)
    (asserts! (is-some safe-username) ERR-INVALID-USERNAME)
    (asserts! (is-some safe-email) ERR-INVALID-EMAIL)
    (asserts! (validate-username (unwrap-panic safe-username)) ERR-INVALID-USERNAME)
    (asserts! (validate-email (unwrap-panic safe-email)) ERR-INVALID-EMAIL)

    ;; Check username availability only if changing
    (if (not (is-eq (get username (unwrap-panic current-user)) (unwrap-panic safe-username)))
      (asserts! (is-none (map-get? taken-usernames (unwrap-panic safe-username))) ERR-USERNAME-TAKEN)
      true
    )

    ;; Update username tracking
    (map-delete taken-usernames (get username (unwrap-panic current-user)))
    (map-set taken-usernames (unwrap-panic safe-username) true)

    ;; Update user record
    (map-set users caller
      (merge (unwrap-panic current-user)
        {
          username: (unwrap-panic safe-username),
          email: (unwrap-panic safe-email)
        }
      )
    )
    (ok true)
  )
)

;; Sets or updates the user's profile image
;; @param image-url: URL string for profile image (max 256 characters)
;; @returns: (ok true) on success, error on failure
(define-public (set-profile-image (image-url (string-utf8 256)))
  (let
    (
      (caller tx-sender)
      (safe-url (as-max-len? image-url u256))
    )
    (asserts! (is-some (map-get? users caller)) ERR-USER-NOT-FOUND)
    (asserts! (is-some safe-url) ERR-INVALID-IMAGE-URL)
    
    (map-set users caller
      (merge (unwrap-panic (map-get? users caller))
        { profile-image: safe-url }
      )
    )
    (ok true)
  )
)

;; Removes the user's profile image
;; @returns: (ok true) on success, error on failure
(define-public (clear-profile-image)
  (let
    ((caller tx-sender))
    (asserts! (is-some (map-get? users caller)) ERR-USER-NOT-FOUND)
    
    (map-set users caller
      (merge (unwrap-panic (map-get? users caller))
        { profile-image: none }
      )
    )
    (ok true)
  )
)

;; Permanently deletes the user's profile and frees up their username
;; @returns: (ok true) on success, error on failure
(define-public (delete-profile)
  (let
    ((caller tx-sender))
    (asserts! (is-some (map-get? users caller)) ERR-USER-NOT-FOUND)
    
    ;; Remove user data and free username
    (map-delete users caller)
    (var-set user-count (- (var-get user-count) u1))
    (ok true)
  )
)

;; READ-ONLY FUNCTIONS - IDENTITY QUERIES

;; Retrieves complete user information for a given principal
;; @param user: Principal address to query
;; @returns: User data map or none if not found
(define-read-only (get-user-info (user principal))
  (map-get? users user)
)

;; Returns the total number of registered users in the system
;; @returns: Current user count as uint
(define-read-only (get-user-count)
  (var-get user-count)
)

;; Checks if a principal has registered an identity
;; @param user: Principal address to check
;; @returns: true if registered, false otherwise
(define-read-only (is-user-registered (user principal))
  (is-some (map-get? users user))
)

;; Checks if a username is available for registration
;; @param username: Username to check availability for
;; @returns: (ok true) if available, (ok false) if taken, error if invalid
(define-read-only (is-username-available (username (string-ascii 50)))
  (let
    ((safe-username (as-max-len? username u50)))
    (if (and
          (is-some safe-username)
          (validate-username (unwrap-panic safe-username)))
      (ok (is-none (map-get? taken-usernames (unwrap-panic safe-username))))
      ERR-INVALID-USERNAME
    )
  )
)