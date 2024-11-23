# Library API Documentation

### Core Features
- User Management: Registering, authenticating, updating, and deleting users
- Author Management: Registering, updating, deleting, and listing authors
- Book Management: Adding, updating, deleting, and listing books
- Book-Author Associations: Linking books with authors and managing these associations

## Table of Contents

1. [Authentication](#authentication)
2. [User Routes](#user-routes)
3. [Author Routes](#author-routes)
4. [Book Routes](#book-routes)
5. [Book-Author Association Routes](#book-author-association-routes)

## Authentication

The API uses token-based authentication to secure endpoints. Each request that modifies or retrieves data requires a valid JWT token in the Authorization header.

### Token Usage
Include the token in the `Authorization` header:
```
Authorization: Bearer <your_token_here>
```

## User Routes

### Register a New User
- **Route:** `/user/register`
- **Method:** POST
- **Body:**
  ```json
  {
    "username": "new_user",
    "password": "password123"
  }
  ```
- **Success Response:**
  ```json
  {
    "status": "success",
    "message": "User registered successfully"
  }
  ```

### Authenticate a User
- **Route:** `/user/authenticate`
- **Method:** POST
- **Body:**
  ```json
  {
    "username": "user",
    "password": "password123"
  }
  ```
- **Success Response:**
  ```json
  {
    "status": "success",
    "token": "your_jwt_token_here"
  }
  ```

### Show All Users
- **Route:** `/user/show`
- **Method:** GET
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "data": [
      {
        "user_id": 1,
        "username": "user1"
      }
    ]
  }
  ```

### Update a User
- **Route:** `/user/update`
- **Method:** PUT
- **Body:**
  ```json
  {
    "user_id": 1,
    "username": "updated_user",
    "password": "new_password123"
  }
  ```
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "message": "User updated successfully",
    "token": "new_jwt_token"
  }
  ```

### Delete a User
- **Route:** `/user/delete`
- **Method:** DELETE
- **Body:**
  ```json
  {
    "user_id": 1
  }
  ```
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "message": "User deleted successfully"
  }
  ```

## Author Routes

### Register a New Author
- **Route:** `/author/register`
- **Method:** POST
- **Body:**
  ```json
  {
    "name": "Author Name"
  }
  ```
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "message": "Author registered successfully"
  }
  ```

### Show All Authors
- **Route:** `/author/show`
- **Method:** GET
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "data": [
      {
        "author_id": 1,
        "name": "Author Name"
      }
    ]
  }
  ```

### Update an Author
- **Route:** `/author/update`
- **Method:** PUT
- **Body:**
  ```json
  {
    "author_id": 1,
    "name": "Updated Author Name"
  }
  ```
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "message": "Author updated successfully"
  }
  ```

### Delete an Author
- **Route:** `/author/delete`
- **Method:** DELETE
- **Body:**
  ```json
  {
    "author_id": 1
  }
  ```
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "message": "Author deleted successfully"
  }
  ```

## Book Routes

### Register a New Book
- **Route:** `/book/register`
- **Method:** POST
- **Body:**
  ```json
  {
    "title": "Book Title",
    "author_id": 1
  }
  ```
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "message": "Book registered successfully"
  }
  ```

### Show All Books
- **Route:** `/book/show`
- **Method:** GET
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "data": [
      {
        "book_id": 1,
        "title": "Book Title",
        "author_id": 1
      }
    ]
  }
  ```

### Update a Book
- **Route:** `/book/update`
- **Method:** PUT
- **Body:**
  ```json
  {
    "book_id": 1,
    "title": "Updated Book Title",
    "author_id": 2
  }
  ```
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "message": "Book updated successfully"
  }
  ```

### Delete a Book
- **Route:** `/book/delete`
- **Method:** DELETE
- **Body:**
  ```json
  {
    "book_id": 1
  }
  ```
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "message": "Book deleted successfully"
  }
  ```

## Book-Author Association Routes

### Register a Book-Author Association
- **Route:** `/book_author/register`
- **Method:** POST
- **Body:**
  ```json
  {
    "book_id": 1,
    "author_id": 1
  }
  ```
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "message": "Association created successfully"
  }
  ```

### Show All Book-Author Associations
- **Route:** `/book_author/show`
- **Method:** GET
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "data": [
      {
        "book_id": 1,
        "author_id": 1,
        "book_title": "Book Title",
        "author_name": "Author Name"
      }
    ]
  }
  ```

### Delete a Book-Author Association
- **Route:** `/book_author/delete`
- **Method:** DELETE
- **Body:**
  ```json
  {
    "book_id": 1,
    "author_id": 1
  }
  ```
- **Headers:** Authorization required
- **Success Response:**
  ```json
  {
    "status": "success",
    "message": "Association deleted successfully"
  }
  ```
