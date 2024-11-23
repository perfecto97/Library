```
#Library API Documentation

##Overview

The Library API is a RESTful service that provides functionality for managing books, authors, and their associations within a library system. It supports operations such as registering users, authenticating them, adding books, managing authors, and associating books with authors. The API uses JWT (JSON Web Token) for secure user authentication and token management.

The system includes the following core features:
- **User Management**: Registering, authenticating, updating, and deleting users.
- **Author Management**: Registering, updating, deleting, and listing authors.
- **Book Management**: Adding, updating, deleting, and listing books.
- **Book-Author Associations**: Linking books with authors and managing these associations.

The API is designed to be used in a library management system where users can interact with books and authors in a seamless and secure way.

---

## Table of Contents

1. [Authentication](#authentication)
   - Token-Based Authentication
   - Token Usage
2. [User Routes](#user-routes)
   - Register a New User
   - Authenticate a User
   - Show All Users
   - Update a User
   - Delete a User
3. [Author Routes](#author-routes)
   - Register a New Author
   - Show All Authors
   - Update an Author
   - Delete an Author
4. [Book Routes](#book-routes)
   - Register a New Book
   - Show All Books
   - Update a Book
   - Delete a Book
5. [Book-Author Association Routes](#book-author-association-routes)
   - Register a Book-Author Association
   - Show All Book-Author Associations
   - Update a Book-Author Association
   - Delete a Book-Author Association

---

## Authentication

### Token-Based Authentication

Each request that modifies or retrieves data requires a valid JWT token in the Authorization header. Tokens are generated upon user authentication and must be included in the request header as a Bearer token.

### Token Usage
- **Bearer Token:** Each request must include the token in the `Authorization` header in the format:
  ```
  Authorization: Bearer <your_token_here>
  ```

---

## User Routes

#### 1. Register a New User
- **Route:** `/user/register`
- **Method:** POST
- **Description:** Registers a new user in the system.
- **Request Payload:**
  ```json
  {
    "username": "new_user",
    "password": "password123"
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "status": "success",
      "message": "User registered successfully"
    }
    ```
  - **Error:**
    ```json
    {
      "status": "fail",
      "message": "Username already exists"
    }
    ```

#### 2. Authenticate a User
- **Route:** `/user/authenticate`
- **Method:** POST
- **Description:** Authenticates a user and generates a JWT token.
- **Request Payload:**
  ```json
  {
    "username": "user",
    "password": "password123"
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "status": "success",
      "token": "your_jwt_token_here"
    }
    ```
  - **Error:**
    ```json
    {
      "status": "fail",
      "message": "Invalid credentials"
    }
    ```

#### 3. Show All Users
- **Route:** `/user/show`
- **Method:** GET
- **Description:** Retrieves a list of all users in the system.
- **Headers:** `Authorization: Bearer <your_token_here>`
- **Response:**
  - **Success:**
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

#### 4. Update a User
- **Route:** `/user/update`
- **Method:** PUT
- **Description:** Updates the details of an existing user.
- **Request Payload:**
  ```json
  {
    "token": "your_jwt_token",
    "user_id": 1,
    "username": "updated_user",
    "password": "new_password123"
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "status": "success",
      "message": "User updated successfully",
      "token": "new_jwt_token"
    }
    ```
  - **Error:**
    ```json
    {
      "status": "fail",
      "message": "Unable to update user"
    }
    ```

#### 5. Delete a User
- **Route:** `/user/delete`
- **Method:** DELETE
- **Description:** Deletes an existing user.
- **Request Payload:**
  ```json
  {
    "token": "your_jwt_token",
    "user_id": 1
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "status": "success",
      "message": "User deleted successfully",
      "token": "new_jwt_token"
    }
    ```
  - **Error:**
    ```json
    {
      "status": "fail",
      "message": "Unable to delete user"
    }
    ```

---

## Author Routes

#### 1. Register a New Author
- **Route:** `/author/register`
- **Method:** POST
- **Description:** Registers a new author in the system.
- **Request Payload:**
  ```json
  {
    "name": "Author Name"
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "status": "success",
      "message": "Author registered successfully"
    }
    ```
  - **Error:**
    ```json
    {
      "status": "fail",
      "message": "Author already exists"
    }
    ```

#### 2. Show All Authors
- **Route:** `/author/show`
- **Method:** GET
- **Description:** Retrieves a list of all authors in the system.
- **Headers:** `Authorization: Bearer <your_token_here>`
- **Response:**
  - **Success:**
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

#### 3. Update an Author
- **Route:** `/author/update`
- **Method:** PUT
- **Description:** Updates the details of an existing author.
- **Request Payload:**
  ```json
  {
    "token": "your_jwt_token",
    "author_id": 1,
    "name": "Updated Author Name"
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "status": "success",
      "message": "Author updated successfully",
      "token": "new_jwt_token"
    }
    ```
  - **Error:**
    ```json
    {
      "status": "fail",
      "message": "Unable to update author"
    }
    ```

#### 4. Delete an Author
- **Route:** `/author/delete`
- **Method:** DELETE
- **Description:** Deletes an existing author from the system.
- **Request Payload:**
  ```json
  {
    "token": "your_jwt_token",
    "author_id": 1
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "status": "success",
      "message": "Author deleted successfully",
      "token": "new_jwt_token"
    }
    ```
  - **Error:**
    ```json
    {
      "status": "fail",
      "message": "Unable to delete author"
    }
    ```

---

## Book Routes

#### 1. Register a New Book
- **Route:** `/book/register`
- **Method:** POST
- **Description:** Registers a new book in the system.
- **Request Payload:**
  ```json
  {
    "title": "Book Title",
    "author_id": 1
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "status": "success",
      "message": "Book registered successfully",
      "token": "new_jwt_token"
    }
    ```
  - **Error:**
    ```json
    {
      "status": "fail",
      "message": "Book already exists"
    }
    ```

#### 2. Show All Books
- **Route:** `/book/show`
- **Method:** GET
- **Description:** Retrieves a list of all books in the system.
- **Headers:** `Authorization: Bearer <your_token_here>`
- **Response:**
  - **Success:**
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

#### 3. Update a Book
- **Route:** `/book/update`
- **Method:** PUT
- **Description:** Updates the details of an existing book.
- **Request Payload:**
  ```json


  {
    "token": "your_jwt_token",
    "book_id": 1,
    "title": "Updated Book Title",
    "author_id": 2
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "status": "success",
      "message": "Book updated successfully",
      "token": "new_jwt_token"
    }
    ```
  - **Error:**
    ```json
    {
      "status": "fail",
      "message": "Unable to update book"
    }
    ```

#### 4. Delete a Book
- **Route:** `/book/delete`
- **Method:** DELETE
- **Description:** Deletes an existing book from the system.
- **Request Payload:**
  ```json
  {
    "token": "your_jwt_token",
    "book_id": 1
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "status": "success",
      "message": "Book deleted successfully",
      "token": "new_jwt_token"
    }
    ```
  - **Error:**
    ```json
    {
      "status": "fail",
      "message": "Unable to delete book"
    }
    ```

---

## Book-Author Association Routes

#### 1. Register a Book-Author Association
- **Route:** `/book_author/register`
- **Method:** POST
- **Description:** Creates a new book-author association.
- **Request Payload:**
  ```json
  {
    "book_id": 1,
    "author_id": 1
  }
  ```

#### 2. Show All Book-Author Associations
- **Route:** `/book_author/show`
- **Method:** GET
- **Description:** Retrieves all book-author associations in the system.

#### 3. Update a Book-Author Association
- **Route:** `/book_author/update`
- **Method:** PUT
- **Description:** Updates an existing book-author association.

#### 4. Delete a Book-Author Association
- **Route:** `/book_author/delete`
- **Method:** DELETE
- **Description:** Deletes an existing book-author association.

---
