# BitPass Identity Protocol

### Bitcoin-Native Decentralized Identity & Authentication System

---

## 📖 Overview

**BitPass Identity Protocol** is a decentralized identity and authentication framework built on the **Stacks blockchain**, leveraging Bitcoin’s security model.
It enables users to:

* Create and manage **self-sovereign digital identities**.
* Register unique **usernames** and associated metadata.
* Maintain **profile data** (email, optional profile image).
* Authenticate across Bitcoin-powered applications **without centralized authorities**.

By utilizing **Stacks smart contracts**, BitPass ensures tamper-proof identity records, secure access control, and seamless cross-app authentication.

---

## 🏗 System Architecture

The protocol follows a **modular Clarity contract design** with clearly defined data structures, validation rules, and access controls.

### Core Components

1. **User Registry (`users` map)**

   * Maps each principal to their identity record.
   * Contains `username`, `email`, and optional `profile-image`.

2. **Username Registry (`taken-usernames` map)**

   * Tracks claimed usernames to ensure global uniqueness.

3. **User Counter (`user-count` var)**

   * Maintains the total number of registered identities for analytics and auditing.

4. **Validation Helpers (private functions)**

   * Enforce input constraints (username length, email format, image URL validity).
   * Prevents malformed or duplicate data from entering the system.

---

## 🔑 Contract Architecture

### Error Constants

Standardized error messages are defined to ensure **consistent error handling** and **predictable contract responses**:

* `ERR-USER-EXISTS` – Caller already registered.
* `ERR-USER-NOT-FOUND` – Identity does not exist.
* `ERR-INVALID-USERNAME` – Username validation failed.
* `ERR-INVALID-EMAIL` – Email validation failed.
* `ERR-INVALID-IMAGE-URL` – Profile image invalid.
* `ERR-USERNAME-TAKEN` – Username is already in use.

---

### Data Structures

```clarity
(define-map users principal {
  username: (string-ascii 50),
  email: (string-ascii 100),
  profile-image: (optional (string-utf8 256))
})

(define-map taken-usernames (string-ascii 50) bool)

(define-data-var user-count uint u0)
```

---

### Public Functions

| Function              | Description                                           |
| --------------------- | ----------------------------------------------------- |
| `register-user`       | Registers a new identity with `username` and `email`. |
| `update-profile`      | Updates existing username and/or email.               |
| `set-profile-image`   | Adds or updates profile image URL.                    |
| `clear-profile-image` | Removes the user’s profile image.                     |
| `delete-profile`      | Deletes the user’s identity and frees username.       |

---

### Read-Only Queries

| Function                | Description                                       |
| ----------------------- | ------------------------------------------------- |
| `get-user-info`         | Retrieves full user identity record by principal. |
| `get-user-count`        | Returns the total number of registered users.     |
| `is-user-registered`    | Checks if a principal has an identity.            |
| `is-username-available` | Validates username availability.                  |

---

## 🔄 Data Flow (Identity Lifecycle)

1. **Registration**

   * Caller submits `username` + `email`.
   * Contract validates input, ensures username availability.
   * Identity record stored in `users` map, username marked as taken, counter incremented.

2. **Profile Management**

   * Users can update `username`/`email` or attach a profile image.
   * Username uniqueness re-validated during updates.

3. **Deletion**

   * User deletes profile → entry removed from `users`, counter decremented.
   * (Optional future extension: free up old username for reuse).

4. **Authentication & Querying**

   * Applications can query user profiles for identity verification.
   * Username availability checks support registration UX.

---

## ⚡️ Key Features

* **Self-Sovereign Identity** – Users retain full control.
* **Cross-App Authentication** – Single identity usable across multiple dApps.
* **Bitcoin Security via Stacks** – Identities anchored to Bitcoin’s consensus.
* **No Central Authority** – Trustless identity registry without intermediaries.
* **Extensible Design** – Ready for DID integration, verifiable credentials, and federated identity flows.

---

## 📌 Future Extensions

* **Decentralized Identifier (DID) support**
* **Verifiable credential issuance**
* **Reputation & trust scoring**
* **Social recovery mechanisms**

---

## 🚀 Deployment & Usage

1. Deploy the Clarity contract to your chosen Stacks network (testnet/mainnet).
2. Interact with contract functions using:

   * **Stacks CLI**
   * **Stacks.js SDK**
   * Direct integration into Bitcoin dApps.
