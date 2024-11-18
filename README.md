
# Library Management API

The **Library Management API** is a RESTful web service designed to manage a library system. It provides endpoints to handle **users**, **books**, **authors**, and their relationships. The API ensures secure interactions through JWT-based authentication, including the use of one-time-use tokens for sensitive operations.

## Key Features

1. **User Management**:
   - User registration and authentication with secure password storage.
   - Token-based authentication using JWT.
   - One-time-use tokens for secure operations.
   - Ability to view, update, or delete user accounts.

2. **Book Management**:
   - Add, update, delete, and view books in the library.
   - Each book is uniquely identified and can be linked to one or more authors.

3. **Author Management**:
   - Add, update, delete, and view authors in the library database.
   - Manage the association of authors with books.

4. **Book-Author Relationships**:
   - Establish and view relationships between books and authors.
   - Each relationship links a specific book to one or more authors.

---

## Security Features

- **JWT Authentication**: 
  - Protects most operations by requiring valid tokens.
  - Tokens are signed and verified using a secret key.
  - One-time-use tokens are issued for operations like adding or updating resources to prevent replay attacks.

- **Error Handling**:
  - Descriptive error messages for invalid tokens, unauthorized access, and database issues.
  - Ensures clear feedback for clients and end-users.

- **Validation**:
  - Strict input validation for required fields like `username`, `password`, `title`, and `name`.
  - Prevention of duplicate records for users, books, and authors.

---

## Prerequisites

To set up and run the Library Management API, ensure you have the following:

- XAMPP
- SQLyog (or phpMyAdmin)
- JWT PHP Library
- Node.js
- Composer
- PHP (version 7.2 or higher)
- Slim Framework
- ThunderClient
---

## Table of Contents

1. [User Endpoints](#user-endpoints)
2. [Book Endpoints](#book-endpoints)
3. [Author Endpoints](#author-endpoints)
4. [Book-Author Relationship Endpoints](#book-author-relationship-endpoints)

---

## User Endpoints

### 1. Register User
- **Endpoint:** `POST /user/register`
- **Description:** Registers a new user.
- **Request Body:**
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **Response:**
  - `status: success` if registration is successful.
  - `status: fail` if the username already exists.

---

### 2. Authenticate User
- **Endpoint:** `POST /user/authentication`
- **Description:** Authenticates a user and generates a JWT.
- **Request Body:**
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **Response:**
  - `status: success` with JWT token.
  - `status: fail` if authentication fails.

---

### 3. Login with Token
- **Endpoint:** `POST /user/login`
- **Description:** Validates an existing JWT and generates a one-time-use token.
- **Headers:** `Authorization: Bearer <JWT>`
- **Response:**
  - `status: success` with new one-time-use token.
  - `status: fail` if validation fails.

---

### 4. View User Details
- **Endpoint:** `POST /user/viewuser`
- **Description:** Retrieves user details using a JWT.
- **Request Body:**
  ```json
  {
    "token": "string"
  }
  ```
- **Response:**
  - `status: success` with user details.
  - `status: fail` if the user is not found or token is invalid.

---

### 5. Update User
- **Endpoint:** `POST /user/updateuser`
- **Description:** Updates user details.
- **Request Body:**
  ```json
  {
    "token": "string",
    "username": "string (optional)",
    "password": "string (optional)"
  }
  ```
- **Response:**
  - `status: success` if update is successful.
  - `status: fail` if no changes are made or token is invalid.

---

### 6. Delete User
- **Endpoint:** `POST /user/deleteuser`
- **Description:** Deletes a user account.
- **Request Body:**
  ```json
  {
    "token": "string",
    "userid": "integer (optional)"
  }
  ```
- **Response:**
  - `status: success` if deletion is successful.
  - `status: fail` if user is not found or token is invalid.

---

## Book Endpoints

### 1. Add Book
- **Endpoint:** `POST /book/add`
- **Description:** Adds a new book.
- **Headers:** `Authorization: Bearer <JWT>`
- **Request Body:**
  ```json
  {
    "title": "string"
  }
  ```
- **Response:**
  - `status: success` if book is added.
  - `status: fail` if the book title already exists or token is invalid.

---

### 2. Update Book
- **Endpoint:** `POST /book/update`
- **Description:** Updates book details.
- **Headers:** `Authorization: Bearer <JWT>`
- **Request Body:**
  ```json
  {
    "bookid": "integer",
    "title": "string"
  }
  ```
- **Response:**
  - `status: success` if update is successful.
  - `status: fail` if book is not found or token is invalid.

---

### 3. Delete Book
- **Endpoint:** `POST /book/delete`
- **Description:** Deletes a book.
- **Headers:** `Authorization: Bearer <JWT>`
- **Request Body:**
  ```json
  {
    "bookid": "integer"
  }
  ```
- **Response:**
  - `status: success` if deletion is successful.
  - `status: fail` if book is not found or token is invalid.

---

### 4. View Books
- **Endpoint:** `GET /book/view`
- **Description:** Retrieves a list of all books.
- **Response:**
  - `status: success` with the list of books.
  - `status: fail` if no books are found.

---

## Author Endpoints

### 1. Add Author
- **Endpoint:** `POST /author/add`
- **Description:** Adds a new author.
- **Headers:** `Authorization: Bearer <JWT>`
- **Request Body:**
  ```json
  {
    "name": "string"
  }
  ```
- **Response:**
  - `status: success` if author is added.
  - `status: fail` if the author already exists or token is invalid.

---

### 2. Update Author
- **Endpoint:** `POST /author/update`
- **Description:** Updates author details.
- **Headers:** `Authorization: Bearer <JWT>`
- **Request Body:**
  ```json
  {
    "authorid": "integer",
    "name": "string"
  }
  ```
- **Response:**
  - `status: success` if update is successful.
  - `status: fail` if author is not found or token is invalid.

---

### 3. Delete Author
- **Endpoint:** `POST /author/delete`
- **Description:** Deletes an author.
- **Headers:** `Authorization: Bearer <JWT>`
- **Request Body:**
  ```json
  {
    "authorid": "integer"
  }
  ```
- **Response:**
  - `status: success` if deletion is successful.
  - `status: fail` if author is not found or token is invalid.

---

### 4. View Authors
- **Endpoint:** `GET /author/view`
- **Description:** Retrieves a list of all authors.
- **Response:**
  - `status: success` with the list of authors.
  - `status: fail` if no authors are found.

---

## Book-Author Relationship Endpoints

### 1. Add Relationship
- **Endpoint:** `POST /books_authors/add`
- **Description:** Links a book with an author.
- **Headers:** `Authorization: Bearer <JWT>`
- **Request Body:**
  ```json
  {
    "bookid": "integer",
    "authorid": "integer"
  }
  ```
- **Response:**
  - `status: success` if relationship is added.
  - `status: fail` if the relationship already exists or token is invalid.

---

### 2. View Relationships
- **Endpoint:** `GET /books_authors/view`
- **Description:** Retrieves all book-author relationships.
- **Response:**
  - `status: success` with the list of relationships.
  - `status: fail` if no relationships are found.

---

## Notes
- All endpoints using JWT require proper authorization headers.
- Database connection errors or missing required fields will return a `status: fail` response.
