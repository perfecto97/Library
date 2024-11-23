<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
$config = ['settings' => ['displayErrorDetails' => true]];
$app = new Slim\App($config);

$key = 'server_hack';

function generateToken($user_id) {
    global $key;

    $iat = time();
    $payload = [
        'iss' => 'http://library.org',
        'aud' => 'http://library.com',
        'iat' => $iat,
        'exp' => $iat + 1800,
        "data" => array(
            "user_id" => $user_id
        )
    ];
    $token = JWT::encode($payload, $key, 'HS256');

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "INSERT INTO tokens_tbl (token, user_id, status) VALUES (:token, :user_id, 'active')";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':token', $token);
        $stmt->bindParam(':user_id', $user_id);

        $stmt->execute();
    } catch (PDOException $e) {

    }

    return $token;
}

function validateToken($token) {
    global $key;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM tokens_tbl WHERE token = :token AND status = 'active'";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':token', $token);
        $stmt->execute();
        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($data) {
            $decoded = JWT::decode($token, new Key($key, 'HS256'));
            return $decoded->data->user_id;
        } else {
            return false;
        }
    } catch (PDOException $e) {
        return false;
    }
}

function markTokenAsUsed($token) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE tokens_tbl SET status = 'revoked' = NOW() WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':token', $token);
        $stmt->execute();
    } catch (PDOException $e) {
    }
}

function updateTokenStatus($token, $status) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE tokens_tbl SET status = :status WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':status', $status);
        $stmt->bindParam(':token', $token);
        $stmt->execute();
    } catch (PDOException $e) {
    }
}

$app->post('/user/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM users_tbl WHERE username = :username");
        $stmt->bindParam(':username', $uname);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "username $uname registered!"))));
        } else {
            $sql = "INSERT INTO users_tbl (username, password) VALUES (:username, :password)";
            $stmt = $conn->prepare($sql);
            $hashedPassword = hash('sha256', $pass);
            $stmt->bindParam(':username', $uname);
            $stmt->bindParam(':password', $hashedPassword);
            $stmt->execute();

            $response->getBody()->write(json_encode(array("status" => "successfully added $uname", "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});


$app->post('/user/authenticate', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM users_tbl WHERE username='" . $uname . "' 
                AND password='" . hash('SHA256', $pass) . "'";
        $stmt = $conn->prepare($sql);
        $stmt->execute();

        $data = $stmt->fetchAll();
        if (count($data) == 1) {
            $user_id = $data[0]['user_id'];
            $token = generateToken($user_id);
            $response->getBody()->write(json_encode(array("status" => "successfully generated $uname", "token" => $token, "data" => null)));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Authentication Failed"))));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->get('/user/show', function (Request $request, Response $response) {
    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization missing"))));
    }

    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    $user_id = validateToken($token);

    if (!$user_id) {
        error_log("expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT user_id, username FROM users_tbl");
        $stmt->execute();
        $users_tbl = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($users_tbl) {
            markTokenAsUsed($token);

            $newToken = generateToken($user_id);

            return $response->write(json_encode(array("status" => "the list", "token" => $newToken, "data" => $users_tbl)));
        } else {
            return $response->write(json_encode(array("status" => "fail", "message" => "No users found")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    $conn = null;
});

$app->put('/user/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token is invalid"))));
    }

    if (!isset($data->user_id)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "User ID is invalid"))));
    }

    $token = $data->token;
    $user_idFromToken = validateToken($token);

    if (!$user_idFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $user_idToUpdate = $data->user_id;

    if ($user_idFromToken != $user_idToUpdate) {
        return $response->withStatus(403)->write(json_encode(array("status" => "fail", "data" => array("title" => "You dont have access"))));
    }

    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE users_tbl SET username = :username, password = :password WHERE user_id = :user_id";
        $stmt = $conn->prepare($sql);
        $hashedPassword = hash('sha256', $pass);
        $stmt->bindParam(':username', $uname);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->bindParam(':user_id', $user_idToUpdate);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($user_idFromToken);
        $response->getBody()->write(json_encode(array("status" => "successfully updated $uname", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->delete('/user/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Error: " . json_last_error_msg());
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid payload"))));
    }

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token invalid in payload"))));
    }

    if (!isset($data->user_id)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "User ID invalid in payload"))));
    }

    $token = $data->token;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $useridToDelete = $data->user_id;

    if ($useridFromToken != $useridToDelete) {
        return $response->withStatus(403)->write(json_encode(array("status" => "fail", "data" => array("title" => "Unauthorized action"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM users_tbl WHERE user_id = :user_id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':user_id', $useridToDelete);
        $stmt->execute();

        markTokenAsUsed($token);

        $response->getBody()->write(json_encode(array("status" => "successfully deleted $uname", "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});


$app->post('/author/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token invalid in payload"))));
    }

    if (!isset($data->name)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Name invalid in payload"))));
    }

    $token = $data->token;
    $name = $data->name;
    $user_idFromToken = validateToken($token);

    if (!$user_idFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM author_tbl WHERE name = :name");
        $stmt->bindParam(':name', $name);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Author name already exist"))));
        } else {
            $sql = "INSERT INTO author_tbl (name) VALUES (:name)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':name', $name);
            $stmt->execute();

            markTokenAsUsed($token);

            $newToken = generateToken($user_idFromToken);
            $response->getBody()->write(json_encode(array("status" => "successfully registered $name", "token" => $newToken, "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->get('/author/show', function (Request $request, Response $response) {

    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization invalid"))));
    }

    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    $user_id = validateToken($token);

    if (!$user_id) {
        error_log("expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT author_id, name FROM author_tbl");
        $stmt->execute();
        $author_tbl = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($author_tbl) {
            markTokenAsUsed($token);

            $newToken = generateToken($user_id);

            return $response->write(json_encode(array("status" => "Succesfully load your list", "token" => $newToken, "data" => $author_tbl)));
        } else {
            return $response->write(json_encode(array("status" => "fail", "message" => "No authors")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    $conn = null;
});

$app->put('/author/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token invalid in payload"))));
    }

    if (!isset($data->author_id)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Author ID invalid in payload"))));
    }

    $token = $data->token;
    $user_idFromToken = validateToken($token);

    if (!$user_idFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $author_idToUpdate = $data->author_id;
    $name = $data->name;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE author_tbl SET name = :name WHERE author_id = :author_id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':author_id', $author_idToUpdate);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($user_idFromToken);
        $response->getBody()->write(json_encode(array("status" => "successfully updated $name", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

    $app->delete('/author/delete', function (Request $request, Response $response) {
        $data = json_decode($request->getBody());

        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("JSON Error: " . json_last_error_msg());
            return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid payload"))));
        }

        if (!isset($data->token)) {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token invalid in payload"))));
        }

        if (!isset($data->author_id)) {
            return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Author ID invalid in payload"))));
        }

        $token = $data->token;
        $useridFromToken = validateToken($token);

        if (!$useridFromToken) {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
        }

        $authoridToDelete = $data->author_id;

        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            $sql = "DELETE FROM author_tbl WHERE author_id = :author_id";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':author_id', $authoridToDelete);
            $stmt->execute();

            markTokenAsUsed($token);

            $newToken = generateToken($useridFromToken);

            $response->getBody()->write(json_encode(array("status" => "successfully deleted", "token" => $newToken, "data" => null)));
        } catch (PDOException $e) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }

        $conn = null;
        return $response;
    });


$app->post('/book/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token invalid in payload"))));
    }

    if (!isset($data->title) || !isset($data->author_id)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Title or Author ID invalid in payload"))));
    }

    $token = $data->token;
    $title = $data->title;
    $author_id = $data->author_id;
    $user_idFromToken = validateToken($token);

    if (!$user_idFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM books_tbl WHERE title = :title AND author_id = :author_id");
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':author_id', $author_id);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Book already exists"))));
        } else {
            $sql = "INSERT INTO books_tbl (title, author_id) VALUES (:title, :author_id)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':title', $title);
            $stmt->bindParam(':author_id', $author_id);
            $stmt->execute();

            markTokenAsUsed($token);

            $newToken = generateToken($user_idFromToken);
            $response->getBody()->write(json_encode(array("status" => "successfully added $title with author number $author_id", "token" => $newToken, "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->get('/book/show', function (Request $request, Response $response) {
    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization invalid"))));
    }

    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    $user_id = validateToken($token);

    if (!$user_id) {
        error_log("Invalid or expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT book_id, title, author_id FROM books_tbl");
        $stmt->execute();
        $books_tbl = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($books_tbl) {
            markTokenAsUsed($token);

            $newToken = generateToken($user_id);

            return $response->write(json_encode(array("status" => "success here are the list", "token" => $newToken, "data" => $books_tbl)));
        } else {
            return $response->write(json_encode(array("status" => "fail", "message" => "No books")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    $conn = null;
});

$app->put('/book/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token invalid in payload"))));
    }

    if (!isset($data->book_id)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Book ID invalid in payload"))));
    }

    $token = $data->token;
    $user_idFromToken = validateToken($token);

    if (!$user_idFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $book_idToUpdate = $data->book_id;
    $title = $data->title;
    $author_id = $data->author_id;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE books_tbl SET title = :title, author_id = :author_id WHERE book_id = :book_id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':author_id', $author_id);
        $stmt->bindParam(':book_id', $book_idToUpdate);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($user_idFromToken);
        $response->getBody()->write(json_encode(array("status" => "successfully updated to $title with book $book_idToUpdate and author id $author_id", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->delete('/book/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Error: " . json_last_error_msg());
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid payload"))));
    }

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token invalid in payload"))));
    }

    if (!isset($data->book_id)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Book ID invalid in payload"))));
    }

    $token = $data->token;
    $user_idFromToken = validateToken($token);

    if (!$user_idFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $book_idToDelete = $data->book_id;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM books_tbl WHERE book_id = :book_id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':book_id', $book_idToDelete);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($user_idFromToken);

        $response->getBody()->write(json_encode(array("status" => "successfully deleted book id $book_idToDelete", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->post('/book_author/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token invalid in payload"))));
    }

    if (!isset($data->book_id) || !isset($data->author_id)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Book ID or Author ID invalid in payload"))));
    }

    $token = $data->token;
    $book_id = $data->book_id;
    $author_id = $data->author_id;
    $user_idFromToken = validateToken($token);

    if (!$user_idFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM books_authors WHERE book_id = :book_id AND author_id = :author_id");
        $stmt->bindParam(':book_id', $book_id);
        $stmt->bindParam(':author_id', $author_id);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Book author already exists"))));
        } else {
            $sql = "INSERT INTO books_authors (book_id, author_id) VALUES (:book_id, :author_id)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':book_id', $book_id);
            $stmt->bindParam(':author_id', $author_id);
            $stmt->execute();

            $collection_id = $conn->lastInsertId();

            markTokenAsUsed($token);

            $newToken = generateToken($user_idFromToken);
            $response->getBody()->write(json_encode(array("status" => "successfully added book_id $book_id and author_id $author_id", "collection_id" => $collection_id, "token" => $newToken, "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});


$app->get('/book_author/show', function (Request $request, Response $response) {
    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization invalid"))));
    }

    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    $user_id = validateToken($token);

    if (!$user_id) {
        error_log("Invalid or expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT collection_id, book_id, author_id FROM books_authors");
        $stmt->execute();
        $bookAuthors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($bookAuthors) {
            markTokenAsUsed($token);

            $newToken = generateToken($user_id);

            return $response->write(json_encode(array("status" => "Here are the list", "token" => $newToken, "data" => $bookAuthors)));
        } else {
            return $response->write(json_encode(array("status" => "fail", "message" => "No book authors")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    $conn = null;
});

$app->put('/book_author/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token invalid in payload"))));
    }

    if (!isset($data->collection_id)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Collection ID invalid in payload"))));
    }

    $token = $data->token;
    $user_idFromToken = validateToken($token);

    if (!$user_idFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $collection_idToUpdate = $data->collection_id;
    $book_id = $data->book_id;
    $author_id = $data->author_id;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE books_authors SET book_id = :book_id, author_id = :author_id WHERE collection_id = :collection_id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':book_id', $book_id);
        $stmt->bindParam(':author_id', $author_id);
        $stmt->bindParam(':collection_id', $collection_idToUpdate);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($user_idFromToken);
        $response->getBody()->write(json_encode(array("status" => "successfully updated", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->delete('/book_author/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Error: " . json_last_error_msg());
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid payload"))));
    }

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token invalid in payload"))));
    }

    if (!isset($data->collection_id)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Collection ID invalid in payload"))));
    }

    $token = $data->token;
    $user_idFromToken = validateToken($token);

    if (!$user_idFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "expired token"))));
    }

    $collection_idToDelete = $data->collection_id;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM books_authors WHERE collection_id = :collection_id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':collection_id', $collection_idToDelete);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($user_idFromToken);

        $response->getBody()->write(json_encode(array("status" => "success deleted", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->run();
?>
