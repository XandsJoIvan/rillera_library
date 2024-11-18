<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
$app = new \Slim\App;

//User Related Endpoints Start//
$app->post('/user/register', function (Request $request, Response $response, array $args){

    $data = json_decode($request->getBody());
    $usr = $data->username;
    $pass = $data->password;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the username already exists
        $check = $conn->query("SELECT COUNT(*) FROM users WHERE username = '".$usr."'")->fetchColumn();
        
        if ($check > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", 
            "data" => array("title" => "Username already exists"))));
        } else {
            // If username does not exist, insert the new user
            $sql = "INSERT INTO users (username, password)
            VALUES ('".$usr."', '".hash('SHA256', $pass)."')";

            $conn->exec($sql);

            $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
        }
        
    } catch(PDOException $e) {
        $response->getBody()->write(json_encode(array("status"=>"fail", 
         "data"=>array("title" => $e -> getMessage()))));
    }

    $conn = null;
   
    return $response;
});

//user authenticate
$app->post('/user/authentication', function (Request $request, Response $response, array $args){

    $data = json_decode($request->getBody());
    $usr = $data->username;
    $pass = $data->password;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM users WHERE username = '".$usr."' 
            AND password = '".hash('SHA256', $pass)."'";

        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $data = $stmt->fetchAll();

        if (count($data) == 1) {
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat, // Issued at: current time
                'exp' => $iat + 3600, // Expiration time
                'data' => array(
                    'userid' => $data[0]['userid']  // Fix: Properly include 'userid' in the payload
                )
            ];

            $jwt = JWT::encode($payload, $key, 'HS256');

            // Send response with JWT token
            $response->getBody()->write(
                json_encode(array(
                    "status" => "success",
                    "token" => $jwt,
                    "data" => null
                ))
            );
        } else {
            $response->getBody()->write(
                json_encode(array(
                    "status" => "fail",
                    "data" => array(
                        "title" => "Authentication Failed")
                    )  
                )
            );
        }
        
    } catch(PDOException $e) {
        $response->getBody()->write(json_encode(array("status"=>"fail", 
         "data"=>array("title" => $e -> getMessage()))));
    }

    return $response;
});

$app->post('/user/login', function (Request $request, Response $response, array $args) {

    // Get the 'Authorization' header from the request
    $authHeader = $request->getHeader('Authorization');

    // Check if the Authorization header exists
    if (!isset($authHeader[0])) {
        return $response->withStatus(401)->write(json_encode(array(
            "status" => "fail",
            "message" => "Authorization header not found"
        )));
    }

    // Extract the JWT token from the 'Authorization' header
    $jwt = trim(str_replace('Bearer', '', $authHeader[0]));  // Remove 'Bearer' from the token

    if (empty($jwt)) {
        return $response->withStatus(400)->write(json_encode(array(
            "status" => "fail",
            "message" => "Token is missing in Authorization header"
        )));
    }

    $key = 'server_hack';  // Secret key used for encoding/decoding the JWT

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Decode and verify the JWT received from the Authorization header
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Validate JWT payload structure
        if (!isset($decoded->data->userid)) {
            return $response->withStatus(400)->write(json_encode(array(
                "status" => "fail",
                "message" => "Invalid token: userid missing in token payload"
            )));
        }

        $userid = $decoded->data->userid;  // Assuming 'userid' is in the JWT payload

        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if user exists in the database (optional validation)
        $checkUserStmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE userid = :userid");
        $checkUserStmt->bindParam(':userid', $userid);
        $checkUserStmt->execute();
        $userExists = $checkUserStmt->fetchColumn();

        if ($userExists == 0) {
            return $response->withStatus(400)->write(json_encode(array(
                "status" => "fail",
                "message" => "Invalid user: No such user exists"
            )));
        }

        // Generate a one-time-use JWT token
        $iat = time();  // Issued at time
        $exp = $iat + 600;  // Token valid for 10 minutes (600 seconds)
        $payload = [
            'iss' => 'http://library.org',  // Issuer
            'aud' => 'http://library.com',  // Audience
            'iat' => $iat,  // Issued at time
            'exp' => $exp,  // Expiration time
            'data' => [
                'userid' => $userid  // Include the user ID in the token
            ]
        ];

        // Encode the JWT
        $oneTimeJwt = JWT::encode($payload, $key, 'HS256');

        // Insert the JWT token into the tokens table
        $sql = "INSERT INTO tokens (userid, token) VALUES (:userid, :token)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':userid', $userid);
        $stmt->bindParam(':token', $oneTimeJwt);
        $stmt->execute();

        // Return the one-time-use JWT token in the response
        $response->getBody()->write(json_encode(array(
            "status" => "success",
            "token" => $oneTimeJwt,  // Return the generated JWT
            "data" => null
        )));

    } catch (Exception $e) {
        // If decoding the JWT fails or any other error occurs
        $response->getBody()->write(json_encode(array(
            "status" => "fail",
            "message" => $e->getMessage()
        )));
    }

    return $response;
});

//user signout endpoint
$app->delete('/user/signout', function (Request $request, Response $response, array $args) {

    // Get the 'Authorization' header from the request
    $authHeader = $request->getHeader('Authorization');

    // Check if the Authorization header exists
    if (!isset($authHeader[0])) {
        return $response->withStatus(401)->write(json_encode(array(
            "status" => "fail",
            "message" => "Authorization header not found"
        )));
    }

    // Extract the JWT token from the 'Authorization' header
    $jwt = trim(str_replace('Bearer', '', $authHeader[0]));  // Remove 'Bearer' from the token

    if (empty($jwt)) {
        return $response->withStatus(400)->write(json_encode(array(
            "status" => "fail",
            "message" => "Token is missing in Authorization header"
        )));
    }

    $key = 'server_hack';  // Secret key used for encoding/decoding the JWT

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Decode and verify the JWT received from the Authorization header
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Validate JWT payload structure
        if (!isset($decoded->data->userid)) {
            return $response->withStatus(400)->write(json_encode(array(
                "status" => "fail",
                "message" => "Invalid token: userid missing in token payload"
            )));
        }

        $userid = $decoded->data->userid;  // Assuming 'userid' is in the JWT payload

        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Delete all one-time-use tokens associated with this userid
        $sql = "DELETE FROM tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':userid', $userid);
        $stmt->execute();

        // Return a success message
        $response->getBody()->write(json_encode(array(
            "status" => "success",
            "message" => "All one-time-use tokens deleted for user",
            "data" => null
        )));

    } catch (Exception $e) {
        // If decoding the JWT fails or any other error occurs
        $response->getBody()->write(json_encode(array(
            "status" => "fail",
            "message" => $e->getMessage()
        )));
    }

    return $response;
});

//view user endpoint
$app->post('/user/viewuser', function (Request $request, Response $response, array $args){

    // Get the data from the request body
    $data = json_decode($request->getBody());
    $jwt = $data->token; // Extract the JWT from the request body

    $key = 'server_hack'; // This key should match the one used in authentication

    try {
        // Decode the JWT
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Extract the userid from the decoded JWT payload
        $userid = $decoded->data[0];

        // Database connection
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        // Connect to the database and fetch user info based on userid
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Prepare the SQL query to fetch user information
        $stmt = $conn->prepare("SELECT * FROM users WHERE userid = :userid");
        $stmt->bindParam(':userid', $userid);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Check if a user was found
        if ($user) {
            // Return the user data as a response
            $response->getBody()->write(
                json_encode(array(
                    "status" => "success",
                    "data" => $user
                ))
            );
        } else {
            // No user found for the given userid
            $response->getBody()->write(
                json_encode(array(
                    "status" => "fail",
                    "data" => array("title" => "User not found")
                ))
            );
        }

    } catch (Exception $e) {
        // Handle any exceptions, such as invalid JWT or database errors
        $response->getBody()->write(
            json_encode(array(
                "status" => "fail",
                "data" => array("title" => $e->getMessage())
            ))
        );
    }

    return $response;
});

$app->post('/user/updateuser', function (Request $request, Response $response, array $args){

    // Get the data from the request body
    $data = json_decode($request->getBody());
    $jwt = $data->token; // Extract the JWT from the request body

    $key = 'server_hack'; // This key should match the one used in authentication

    try {
        // Decode the JWT to get the user info
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Extract the userid from the decoded JWT payload
        $userid = $decoded->data[0];

        // Database connection
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Prepare the SQL update query dynamically based on provided fields
        $fieldsToUpdate = [];
        $parameters = [];

        // Check which fields are being updated and add them to the query
        if (!empty($data->username)) {
            $fieldsToUpdate[] = "username = :username";
            $parameters[':username'] = $data->username;
        }

        if (!empty($data->password)) {
            $fieldsToUpdate[] = "password = :password";
            $parameters[':password'] = hash('SHA256', $data->password); // Hash the new password
        }

        if (count($fieldsToUpdate) > 0) {
            // Construct the final SQL query with dynamic updates
            $sql = "UPDATE users SET " . implode(", ", $fieldsToUpdate) . " WHERE userid = :userid";
            $parameters[':userid'] = $userid;

            $stmt = $conn->prepare($sql);
            $stmt->execute($parameters);

            // Check if any rows were updated
            if ($stmt->rowCount() > 0) {
                $response->getBody()->write(
                    json_encode(array(
                        "status" => "success",
                        "data" => array("message" => "User updated successfully")
                    ))
                );
            } else {
                $response->getBody()->write(
                    json_encode(array(
                        "status" => "fail",
                        "data" => array("message" => "No changes were made or user not found")
                    ))
                );
            }
        } else {
            // No fields were provided for update
            $response->getBody()->write(
                json_encode(array(
                    "status" => "fail",
                    "data" => array("message" => "No fields provided to update")
                ))
            );
        }

    } catch (Exception $e) {
        // Handle exceptions, such as invalid JWT or database errors
        $response->getBody()->write(
            json_encode(array(
                "status" => "fail",
                "data" => array("message" => $e->getMessage())
            ))
        );
    }

    return $response;
});

$app->post('/user/deleteuser', function (Request $request, Response $response, array $args){

    // Get the data from the request body
    $data = json_decode($request->getBody());
    $jwt = $data->token; // Extract the JWT from the request body

    $key = 'server_hack'; // This key should match the one used in authentication

    try {
        // Decode the JWT to get the user info
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Extract the userid from the decoded JWT payload
        $userid = $decoded->data[0];

        // Check if the user ID to delete is provided in the request
        if (!isset($data->userid)) {
            // If no user ID is provided, we assume the user wants to delete their own account
            $deleteUserId = $userid;
        } else {
            // Otherwise, use the provided user ID
            $deleteUserId = $data->userid;
        }

        // Database connection
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the user exists before deleting
        $stmt = $conn->prepare("SELECT * FROM users WHERE userid = :userid");
        $stmt->bindParam(':userid', $deleteUserId);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // If user exists, proceed with deletion
            $deleteStmt = $conn->prepare("DELETE FROM users WHERE userid = :userid");
            $deleteStmt->bindParam(':userid', $deleteUserId);
            $deleteStmt->execute();

            $response->getBody()->write(
                json_encode(array(
                    "status" => "success",
                    "data" => array("message" => "User deleted successfully")
                ))
            );
        } else {
            // User not found
            $response->getBody()->write(
                json_encode(array(
                    "status" => "fail",
                    "data" => array("message" => "User not found")
                ))
            );
        }

    } catch (Exception $e) {
        // Handle exceptions, such as invalid JWT or database errors
        $response->getBody()->write(
            json_encode(array(
                "status" => "fail",
                "data" => array("message" => $e->getMessage())
            ))
        );
    }

    return $response;
});

//User Related Endpoints End//


//Book Related Endpoints//
$app->post('/book/add', function (Request $request, Response $response, array $args){

    // Get the 'Authorization' header from the request
    $authHeader = $request->getHeader('Authorization');

    // Check if the Authorization header exists
    if (!isset($authHeader[0])) {
        return $response->withStatus(401)->write(json_encode(array(
            "status" => "fail",
            "message" => "Authorization header not found"
        )));
    }

    // Extract the JWT token from the 'Authorization' header
    $jwt = trim(str_replace('Bearer', '', $authHeader[0]));  // Remove 'Bearer' from the token

    if (empty($jwt)) {
        return $response->withStatus(400)->write(json_encode(array(
            "status" => "fail",
            "message" => "Token is missing in Authorization header"
        )));
    }

    $key = 'server_hack';  // Secret key used for encoding/decoding the JWT

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Decode and verify the one-time-use JWT from the Authorization header
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Extract user data from JWT (userid)
        if (!isset($decoded->data->userid)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid token: userid missing in token payload"
            ]));
        }

        $userid = $decoded->data->userid;  // Extract the userid from the JWT payload

        // Check if the token is valid (exists in the tokens table)
        $checkTokenStmt = $conn->prepare("SELECT COUNT(*) FROM tokens WHERE token = :token AND userid = :userid");
        $checkTokenStmt->bindParam(':token', $jwt);
        $checkTokenStmt->bindParam(':userid', $userid);
        $checkTokenStmt->execute();
        $tokenExists = $checkTokenStmt->fetchColumn();

        if ($tokenExists == 0) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid or expired one-time-use token"
            ]));
        }

        // Now we proceed with adding the book

        // Get the book title from the request body
        $data = json_decode($request->getBody());

        if (!isset($data->title) || empty($data->title)) {
            return $response->withStatus(400)->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Book title is required"]
            ]));
        }
        $bookTitle = $data->title;

        // Check if the book title already exists
        $check = $conn->prepare("SELECT COUNT(*) FROM books WHERE title = :title");
        $check->bindParam(':title', $bookTitle);
        $check->execute();
        $bookExists = $check->fetchColumn();

        if ($bookExists > 0) {
            // Book already exists
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Book title already exists"]
            ]));
        } else {
            // Insert the new book into the database
            $stmt = $conn->prepare("INSERT INTO books (title) VALUES (:title)");
            $stmt->bindParam(':title', $bookTitle);
            $stmt->execute();

            // Delete the used one-time-use token
            $deleteTokenStmt = $conn->prepare("DELETE FROM tokens WHERE token = :token AND userid = :userid");
            $deleteTokenStmt->bindParam(':token', $jwt);
            $deleteTokenStmt->bindParam(':userid', $userid);
            $deleteTokenStmt->execute();

            // Generate a new one-time-use JWT token
            $iat = time();  // Issued at time
            $exp = $iat + 600;  // Token valid for 10 minutes (600 seconds)
            $newPayload = [
                'iss' => 'http://library.org',  // Issuer
                'aud' => 'http://library.com',  // Audience
                'iat' => $iat,  // Issued at time
                'exp' => $exp,  // Expiration time
                'data' => [
                    'userid' => $userid  // Include the user ID in the token
                ]
            ];

            // Encode the JWT
            $newToken = JWT::encode($newPayload, $key, 'HS256');

            // Insert the new token into the tokens table
            $insertTokenStmt = $conn->prepare("INSERT INTO tokens (userid, token) VALUES (:userid, :token)");
            $insertTokenStmt->bindParam(':userid', $userid);
            $insertTokenStmt->bindParam(':token', $newToken);
            $insertTokenStmt->execute();

            // Return the success message and the new one-time-use JWT token
            $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => [
                    "message" => "Book added successfully",
                    "new_token" => $newToken
                ]
            ]));
        }

    } catch (Exception $e) {
        // Handle exceptions such as invalid JWT or database errors
        $response->getBody()->write(json_encode([
            "status" => "fail",
            "data" => ["message" => $e->getMessage()]
        ]));
    }

    return $response;
});

$app->post('/book/update', function (Request $request, Response $response, array $args){

    // Get the 'Authorization' header from the request
    $authHeader = $request->getHeader('Authorization');

    // Check if the Authorization header exists
    if (!isset($authHeader[0])) {
        return $response->withStatus(401)->write(json_encode(array(
            "status" => "fail",
            "message" => "Authorization header not found"
        )));
    }

    // Extract the JWT token from the 'Authorization' header
    $jwt = trim(str_replace('Bearer', '', $authHeader[0]));  // Remove 'Bearer' from the token

    if (empty($jwt)) {
        return $response->withStatus(400)->write(json_encode(array(
            "status" => "fail",
            "message" => "Token is missing in Authorization header"
        )));
    }

    $key = 'server_hack';  // Secret key used for encoding/decoding the JWT

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Decode and verify the JWT from the Authorization header
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Validate JWT payload structure
        if (!isset($decoded->data->userid)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid token: userid missing in token payload"
            ]));
        }

        $userid = $decoded->data->userid;

        // Check if the token is valid (exists in the tokens table)
        $checkTokenStmt = $conn->prepare("SELECT COUNT(*) FROM tokens WHERE token = :token AND userid = :userid");
        $checkTokenStmt->bindParam(':token', $jwt);
        $checkTokenStmt->bindParam(':userid', $userid);
        $checkTokenStmt->execute();
        $tokenExists = $checkTokenStmt->fetchColumn();

        if ($tokenExists == 0) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid or expired one-time-use token"
            ]));
        }

        // Get bookid and new title from the request body
        $data = json_decode($request->getBody());

        if (!isset($data->bookid) || !isset($data->title) || empty($data->title)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Book ID and new title are required"]
            ]));
        }

        $bookId = $data->bookid;
        $newTitle = $data->title;

        // Check if the book exists
        $stmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE bookid = :bookid");
        $stmt->bindParam(':bookid', $bookId);
        $stmt->execute();
        $bookExists = $stmt->fetchColumn();

        if ($bookExists > 0) {
            // Update the book title
            $updateStmt = $conn->prepare("UPDATE books SET title = :title WHERE bookid = :bookid");
            $updateStmt->bindParam(':title', $newTitle);
            $updateStmt->bindParam(':bookid', $bookId);
            $updateStmt->execute();

            // Delete the used one-time-use token
            $deleteTokenStmt = $conn->prepare("DELETE FROM tokens WHERE token = :token AND userid = :userid");
            $deleteTokenStmt->bindParam(':token', $jwt);
            $deleteTokenStmt->bindParam(':userid', $userid);
            $deleteTokenStmt->execute();

            // Generate a new one-time-use JWT token
            $iat = time();  // Issued at time
            $exp = $iat + 600;  // Token valid for 10 minutes (600 seconds)
            $newPayload = [
                'iss' => 'http://library.org',  // Issuer
                'aud' => 'http://library.com',  // Audience
                'iat' => $iat,  // Issued at time
                'exp' => $exp,  // Expiration time
                'data' => [
                    'userid' => $userid  // Include the user ID in the token
                ]
            ];

            // Encode the JWT
            $newToken = JWT::encode($newPayload, $key, 'HS256');

            // Insert the new token into the tokens table
            $insertTokenStmt = $conn->prepare("INSERT INTO tokens (userid, token) VALUES (:userid, :token)");
            $insertTokenStmt->bindParam(':userid', $userid);
            $insertTokenStmt->bindParam(':token', $newToken);
            $insertTokenStmt->execute();

            // Return the success message and the new one-time-use JWT token
            $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => [
                    "message" => "Book updated successfully",
                    "new_token" => $newToken
                ]
            ]));
        } else {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Book not found"]
            ]));
        }

    } catch (Exception $e) {
        // Handle exceptions such as invalid JWT or database errors
        $response->getBody()->write(json_encode([
            "status" => "fail",
            "data" => ["message" => $e->getMessage()]
        ]));
    }

    return $response;
});

$app->post('/book/delete', function (Request $request, Response $response, array $args){

    // Get the 'Authorization' header from the request
    $authHeader = $request->getHeader('Authorization');

    // Check if the Authorization header exists
    if (!isset($authHeader[0])) {
        return $response->withStatus(401)->write(json_encode(array(
            "status" => "fail",
            "message" => "Authorization header not found"
        )));
    }

    // Extract the JWT token from the 'Authorization' header
    $jwt = trim(str_replace('Bearer', '', $authHeader[0]));  // Remove 'Bearer' from the token

    if (empty($jwt)) {
        return $response->withStatus(400)->write(json_encode(array(
            "status" => "fail",
            "message" => "Token is missing in Authorization header"
        )));
    }

    $key = 'server_hack';  // Secret key used for encoding/decoding the JWT

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Decode and verify the JWT from the Authorization header
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Validate JWT payload structure
        if (!isset($decoded->data->userid)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid token: userid missing in token payload"
            ]));
        }

        $userid = $decoded->data->userid;

        // Check if the token is valid (exists in the tokens table)
        $checkTokenStmt = $conn->prepare("SELECT COUNT(*) FROM tokens WHERE token = :token AND userid = :userid");
        $checkTokenStmt->bindParam(':token', $jwt);
        $checkTokenStmt->bindParam(':userid', $userid);
        $checkTokenStmt->execute();
        $tokenExists = $checkTokenStmt->fetchColumn();

        if ($tokenExists == 0) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid or expired one-time-use token"
            ]));
        }

        // Get bookid from the request body
        $data = json_decode($request->getBody());

        if (!isset($data->bookid)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Book ID is required"]
            ]));
        }

        $bookId = $data->bookid;

        // Check if the book exists
        $stmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE bookid = :bookid");
        $stmt->bindParam(':bookid', $bookId);
        $stmt->execute();
        $bookExists = $stmt->fetchColumn();

        if ($bookExists > 0) {
            // Delete the book
            $deleteStmt = $conn->prepare("DELETE FROM books WHERE bookid = :bookid");
            $deleteStmt->bindParam(':bookid', $bookId);
            $deleteStmt->execute();

            // Delete the used one-time-use token
            $deleteTokenStmt = $conn->prepare("DELETE FROM tokens WHERE token = :token AND userid = :userid");
            $deleteTokenStmt->bindParam(':token', $jwt);
            $deleteTokenStmt->bindParam(':userid', $userid);
            $deleteTokenStmt->execute();

            // Generate a new one-time-use JWT token
            $iat = time();  // Issued at time
            $exp = $iat + 600;  // Token valid for 10 minutes (600 seconds)
            $newPayload = [
                'iss' => 'http://library.org',  // Issuer
                'aud' => 'http://library.com',  // Audience
                'iat' => $iat,  // Issued at time
                'exp' => $exp,  // Expiration time
                'data' => [
                    'userid' => $userid  // Include the user ID in the token
                ]
            ];

            // Encode the JWT
            $newToken = JWT::encode($newPayload, $key, 'HS256');

            // Insert the new token into the tokens table
            $insertTokenStmt = $conn->prepare("INSERT INTO tokens (userid, token) VALUES (:userid, :token)");
            $insertTokenStmt->bindParam(':userid', $userid);
            $insertTokenStmt->bindParam(':token', $newToken);
            $insertTokenStmt->execute();

            // Return the success message and the new one-time-use JWT token
            $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => [
                    "message" => "Book deleted successfully",
                    "new_token" => $newToken
                ]
            ]));
        } else {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Book not found"]
            ]));
        }

    } catch (Exception $e) {
        // Handle exceptions such as invalid JWT or database errors
        $response->getBody()->write(json_encode([
            "status" => "fail",
            "data" => ["message" => $e->getMessage()]
        ]));
    }

    return $response;
});
$app->get('/book/view', function (Request $request, Response $response, array $args){

    // Database connection
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch all books from the database
        $stmt = $conn->query("SELECT * FROM books");
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($books) {
            // Return the books data
            $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => $books
            ]));
        } else {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "No books found"]
            ]));
        }

    } catch (Exception $e) {
        // Handle exceptions such as database errors
        $response->getBody()->write(json_encode([
            "status" => "fail",
            "data" => ["message" => $e->getMessage()]
        ]));
    }

    return $response;
});

//Book related endpoints end//

//author related endpoints start//
$app->post('/author/add', function (Request $request, Response $response, array $args){

    // Get the 'Authorization' header from the request
    $authHeader = $request->getHeader('Authorization');

    // Check if the Authorization header exists
    if (!isset($authHeader[0])) {
        return $response->withStatus(401)->write(json_encode(array(
            "status" => "fail",
            "message" => "Authorization header not found"
        )));
    }

    // Extract the JWT token from the 'Authorization' header
    $jwt = trim(str_replace('Bearer', '', $authHeader[0]));  // Remove 'Bearer' from the token

    if (empty($jwt)) {
        return $response->withStatus(400)->write(json_encode(array(
            "status" => "fail",
            "message" => "Token is missing in Authorization header"
        )));
    }

    $key = 'server_hack';  // Secret key used for encoding/decoding the JWT

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Decode and verify the JWT from the Authorization header
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Validate JWT payload structure
        if (!isset($decoded->data->userid)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid token: userid missing in token payload"
            ]));
        }

        $userid = $decoded->data->userid;

        // Check if the token is valid (exists in the tokens table)
        $checkTokenStmt = $conn->prepare("SELECT COUNT(*) FROM tokens WHERE token = :token AND userid = :userid");
        $checkTokenStmt->bindParam(':token', $jwt);
        $checkTokenStmt->bindParam(':userid', $userid);
        $checkTokenStmt->execute();
        $tokenExists = $checkTokenStmt->fetchColumn();

        if ($tokenExists == 0) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid or expired one-time-use token"
            ]));
        }

        // Get author name from the request body
        $data = json_decode($request->getBody());

        if (!isset($data->name) || empty($data->name)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Author name is required"]
            ]));
        }

        $authorName = $data->name;

        // Check if the author name already exists
        $check = $conn->prepare("SELECT COUNT(*) FROM authors WHERE name = :name");
        $check->bindParam(':name', $authorName);
        $check->execute();
        $authorExists = $check->fetchColumn();

        if ($authorExists > 0) {
            // Author already exists
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Author already exists"]
            ]));
        } else {
            // Insert the new author into the database
            $stmt = $conn->prepare("INSERT INTO authors (name) VALUES (:name)");
            $stmt->bindParam(':name', $authorName);
            $stmt->execute();

            // Delete the used one-time-use token
            $deleteTokenStmt = $conn->prepare("DELETE FROM tokens WHERE token = :token AND userid = :userid");
            $deleteTokenStmt->bindParam(':token', $jwt);
            $deleteTokenStmt->bindParam(':userid', $userid);
            $deleteTokenStmt->execute();

            // Generate a new one-time-use JWT token
            $iat = time();  // Issued at time
            $exp = $iat + 600;  // Token valid for 10 minutes (600 seconds)
            $newPayload = [
                'iss' => 'http://library.org',  // Issuer
                'aud' => 'http://library.com',  // Audience
                'iat' => $iat,  // Issued at time
                'exp' => $exp,  // Expiration time
                'data' => [
                    'userid' => $userid  // Include the user ID in the token
                ]
            ];

            // Encode the JWT
            $newToken = JWT::encode($newPayload, $key, 'HS256');

            // Insert the new token into the tokens table
            $insertTokenStmt = $conn->prepare("INSERT INTO tokens (userid, token) VALUES (:userid, :token)");
            $insertTokenStmt->bindParam(':userid', $userid);
            $insertTokenStmt->bindParam(':token', $newToken);
            $insertTokenStmt->execute();

            // Return the success message and the new one-time-use JWT token
            $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => [
                    "message" => "Author added successfully",
                    "new_token" => $newToken
                ]
            ]));
        }

    } catch (Exception $e) {
        // Handle exceptions such as invalid JWT or database errors
        $response->getBody()->write(json_encode([
            "status" => "fail",
            "data" => ["message" => $e->getMessage()]
        ]));
    }

    return $response;
});

$app->post('/author/update', function (Request $request, Response $response, array $args){

    // Get the 'Authorization' header from the request
    $authHeader = $request->getHeader('Authorization');

    // Check if the Authorization header exists
    if (!isset($authHeader[0])) {
        return $response->withStatus(401)->write(json_encode(array(
            "status" => "fail",
            "message" => "Authorization header not found"
        )));
    }

    // Extract the JWT token from the 'Authorization' header
    $jwt = trim(str_replace('Bearer', '', $authHeader[0]));  // Remove 'Bearer' from the token

    if (empty($jwt)) {
        return $response->withStatus(400)->write(json_encode(array(
            "status" => "fail",
            "message" => "Token is missing in Authorization header"
        )));
    }

    $key = 'server_hack';  // Secret key used for encoding/decoding the JWT

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Decode and verify the JWT from the Authorization header
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Validate JWT payload structure
        if (!isset($decoded->data->userid)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid token: userid missing in token payload"
            ]));
        }

        $userid = $decoded->data->userid;

        // Check if the token is valid (exists in the tokens table)
        $checkTokenStmt = $conn->prepare("SELECT COUNT(*) FROM tokens WHERE token = :token AND userid = :userid");
        $checkTokenStmt->bindParam(':token', $jwt);
        $checkTokenStmt->bindParam(':userid', $userid);
        $checkTokenStmt->execute();
        $tokenExists = $checkTokenStmt->fetchColumn();

        if ($tokenExists == 0) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid or expired one-time-use token"
            ]));
        }

        // Get authorid and new name from the request body
        $data = json_decode($request->getBody());

        if (!isset($data->authorid) || !isset($data->name) || empty($data->name)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Author ID and new name are required"]
            ]));
        }

        $authorId = $data->authorid;
        $newName = $data->name;

        // Check if the author exists
        $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE authorid = :authorid");
        $stmt->bindParam(':authorid', $authorId);
        $stmt->execute();
        $authorExists = $stmt->fetchColumn();

        if ($authorExists > 0) {
            // Update the author name
            $updateStmt = $conn->prepare("UPDATE authors SET name = :name WHERE authorid = :authorid");
            $updateStmt->bindParam(':name', $newName);
            $updateStmt->bindParam(':authorid', $authorId);
            $updateStmt->execute();

            // Delete the used one-time-use token
            $deleteTokenStmt = $conn->prepare("DELETE FROM tokens WHERE token = :token AND userid = :userid");
            $deleteTokenStmt->bindParam(':token', $jwt);
            $deleteTokenStmt->bindParam(':userid', $userid);
            $deleteTokenStmt->execute();

            // Generate a new one-time-use JWT token
            $iat = time();  // Issued at time
            $exp = $iat + 600;  // Token valid for 10 minutes (600 seconds)
            $newPayload = [
                'iss' => 'http://library.org',  // Issuer
                'aud' => 'http://library.com',  // Audience
                'iat' => $iat,  // Issued at time
                'exp' => $exp,  // Expiration time
                'data' => [
                    'userid' => $userid  // Include the user ID in the token
                ]
            ];

            // Encode the JWT
            $newToken = JWT::encode($newPayload, $key, 'HS256');

            // Insert the new token into the tokens table
            $insertTokenStmt = $conn->prepare("INSERT INTO tokens (userid, token) VALUES (:userid, :token)");
            $insertTokenStmt->bindParam(':userid', $userid);
            $insertTokenStmt->bindParam(':token', $newToken);
            $insertTokenStmt->execute();

            // Return the success message and the new one-time-use JWT token
            $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => [
                    "message" => "Author updated successfully",
                    "new_token" => $newToken
                ]
            ]));
        } else {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Author not found"]
            ]));
        }

    } catch (Exception $e) {
        // Handle exceptions such as invalid JWT or database errors
        $response->getBody()->write(json_encode([
            "status" => "fail",
            "data" => ["message" => $e->getMessage()]
        ]));
    }

    return $response;
});

$app->post('/author/delete', function (Request $request, Response $response, array $args){

    // Get the 'Authorization' header from the request
    $authHeader = $request->getHeader('Authorization');

    // Check if the Authorization header exists
    if (!isset($authHeader[0])) {
        return $response->withStatus(401)->write(json_encode(array(
            "status" => "fail",
            "message" => "Authorization header not found"
        )));
    }

    // Extract the JWT token from the 'Authorization' header
    $jwt = trim(str_replace('Bearer', '', $authHeader[0]));  // Remove 'Bearer' from the token

    if (empty($jwt)) {
        return $response->withStatus(400)->write(json_encode(array(
            "status" => "fail",
            "message" => "Token is missing in Authorization header"
        )));
    }

    $key = 'server_hack';  // Secret key used for encoding/decoding the JWT

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Decode and verify the JWT from the Authorization header
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Validate JWT payload structure
        if (!isset($decoded->data->userid)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid token: userid missing in token payload"
            ]));
        }

        $userid = $decoded->data->userid;

        // Check if the token is valid (exists in the tokens table)
        $checkTokenStmt = $conn->prepare("SELECT COUNT(*) FROM tokens WHERE token = :token AND userid = :userid");
        $checkTokenStmt->bindParam(':token', $jwt);
        $checkTokenStmt->bindParam(':userid', $userid);
        $checkTokenStmt->execute();
        $tokenExists = $checkTokenStmt->fetchColumn();

        if ($tokenExists == 0) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid or expired one-time-use token"
            ]));
        }

        // Get authorid from the request body
        $data = json_decode($request->getBody());

        if (!isset($data->authorid)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Author ID is required"]
            ]));
        }

        $authorId = $data->authorid;

        // Check if the author exists
        $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE authorid = :authorid");
        $stmt->bindParam(':authorid', $authorId);
        $stmt->execute();
        $authorExists = $stmt->fetchColumn();

        if ($authorExists > 0) {
            // Delete the author
            $deleteStmt = $conn->prepare("DELETE FROM authors WHERE authorid = :authorid");
            $deleteStmt->bindParam(':authorid', $authorId);
            $deleteStmt->execute();

            // Delete the used one-time-use token
            $deleteTokenStmt = $conn->prepare("DELETE FROM tokens WHERE token = :token AND userid = :userid");
            $deleteTokenStmt->bindParam(':token', $jwt);
            $deleteTokenStmt->bindParam(':userid', $userid);
            $deleteTokenStmt->execute();

            // Generate a new one-time-use JWT token
            $iat = time();  // Issued at time
            $exp = $iat + 600;  // Token valid for 10 minutes (600 seconds)
            $newPayload = [
                'iss' => 'http://library.org',  // Issuer
                'aud' => 'http://library.com',  // Audience
                'iat' => $iat,  // Issued at time
                'exp' => $exp,  // Expiration time
                'data' => [
                    'userid' => $userid  // Include the user ID in the token
                ]
            ];

            // Encode the JWT
            $newToken = JWT::encode($newPayload, $key, 'HS256');

            // Insert the new token into the tokens table
            $insertTokenStmt = $conn->prepare("INSERT INTO tokens (userid, token) VALUES (:userid, :token)");
            $insertTokenStmt->bindParam(':userid', $userid);
            $insertTokenStmt->bindParam(':token', $newToken);
            $insertTokenStmt->execute();

            // Return the success message and the new one-time-use JWT token
            $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => [
                    "message" => "Author deleted successfully",
                    "new_token" => $newToken
                ]
            ]));
        } else {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Author not found"]
            ]));
        }

    } catch (Exception $e) {
        // Handle exceptions such as invalid JWT or database errors
        $response->getBody()->write(json_encode([
            "status" => "fail",
            "data" => ["message" => $e->getMessage()]
        ]));
    }

    return $response;
});

$app->get('/author/view', function (Request $request, Response $response, array $args){

    // Database connection
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch all authors from the database
        $stmt = $conn->query("SELECT * FROM authors");
        $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($authors) {
            // Return the authors data
            $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => $authors
            ]));
        } else {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "No authors found"]
            ]));
        }

    } catch (Exception $e) {
        // Handle exceptions such as database errors
        $response->getBody()->write(json_encode([
            "status" => "fail",
            "data" => ["message" => $e->getMessage()]
        ]));
    }

    return $response;
});
//author related endpoints end//


//book-author related endpoint start//
$app->post('/books_authors/add', function (Request $request, Response $response, array $args){

    // Get the 'Authorization' header from the request
    $authHeader = $request->getHeader('Authorization');

    // Check if the Authorization header exists
    if (!isset($authHeader[0])) {
        return $response->withStatus(401)->write(json_encode(array(
            "status" => "fail",
            "message" => "Authorization header not found"
        )));
    }

    // Extract the JWT token from the 'Authorization' header
    $jwt = trim(str_replace('Bearer', '', $authHeader[0]));  // Remove 'Bearer' from the token

    if (empty($jwt)) {
        return $response->withStatus(400)->write(json_encode(array(
            "status" => "fail",
            "message" => "Token is missing in Authorization header"
        )));
    }

    $key = 'server_hack';  // Secret key used for encoding/decoding the JWT

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Decode and verify the JWT from the Authorization header
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Validate JWT payload structure
        if (!isset($decoded->data->userid)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid token: userid missing in token payload"
            ]));
        }

        $userid = $decoded->data->userid;

        // Check if the token is valid (exists in the tokens table)
        $checkTokenStmt = $conn->prepare("SELECT COUNT(*) FROM tokens WHERE token = :token AND userid = :userid");
        $checkTokenStmt->bindParam(':token', $jwt);
        $checkTokenStmt->bindParam(':userid', $userid);
        $checkTokenStmt->execute();
        $tokenExists = $checkTokenStmt->fetchColumn();

        if ($tokenExists == 0) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "message" => "Invalid or expired one-time-use token"
            ]));
        }

        // Get bookid and authorid from the request body
        $data = json_decode($request->getBody());

        if (!isset($data->bookid) || !isset($data->authorid)) {
            return $response->withStatus(400)->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Book ID and Author ID are required"]
            ]));
        }

        $bookId = $data->bookid;
        $authorId = $data->authorid;

        // Prepare SQL query to check if the book-author relationship already exists using INNER JOIN
        $stmt = $conn->prepare("SELECT count(*) as numRecords FROM books
            INNER JOIN books_authors ON books.bookid = books_authors.bookid
            INNER JOIN authors ON authors.authorid = books_authors.authorid
            WHERE books.bookid = :bookid AND authors.authorid = :authorid");

        // Bind parameters to prevent SQL injection
        $stmt->bindParam(':bookid', $bookId);
        $stmt->bindParam(':authorid', $authorId);

        // Execute the query
        $stmt->execute();

        // Fetch the result as associative array
        $count = $stmt->fetch(PDO::FETCH_ASSOC);

        // Check if relationship exists
        if ($count['numRecords'] == 0) {
            // If no record exists, insert the new relationship into 'books_authors'
            $sql = "INSERT INTO books_authors (bookid, authorid) VALUES (:bookid, :authorid)";

            // Prepare the insert statement
            $insertStmt = $conn->prepare($sql);

            // Bind parameters
            $insertStmt->bindParam(':bookid', $bookId);
            $insertStmt->bindParam(':authorid', $authorId);

            // Execute the insert query
            $insertStmt->execute();

            // Delete the used one-time-use token
            $deleteTokenStmt = $conn->prepare("DELETE FROM tokens WHERE token = :token AND userid = :userid");
            $deleteTokenStmt->bindParam(':token', $jwt);
            $deleteTokenStmt->bindParam(':userid', $userid);
            $deleteTokenStmt->execute();

            // Generate a new one-time-use JWT token
            $iat = time();  // Issued at time
            $exp = $iat + 600;  // Token valid for 10 minutes (600 seconds)
            $newPayload = [
                'iss' => 'http://library.org',  // Issuer
                'aud' => 'http://library.com',  // Audience
                'iat' => $iat,  // Issued at time
                'exp' => $exp,  // Expiration time
                'data' => [
                    'userid' => $userid  // Include the user ID in the token
                ]
            ];

            // Encode the JWT
            $newToken = JWT::encode($newPayload, $key, 'HS256');

            // Insert the new token into the tokens table
            $insertTokenStmt = $conn->prepare("INSERT INTO tokens (userid, token) VALUES (:userid, :token)");
            $insertTokenStmt->bindParam(':userid', $userid);
            $insertTokenStmt->bindParam(':token', $newToken);
            $insertTokenStmt->execute();

            // Return success response with the new token
            $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => [
                    "message" => "Relationship between book and author added successfully",
                    "new_token" => $newToken
                ]
            ]));
        } else {
            // If record already exists, return a failure response
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "Relationship between book and author already exists"]
            ]));
        }

    } catch (Exception $e) {
        // Handle exceptions such as invalid JWT or database errors
        $response->getBody()->write(json_encode([
            "status" => "fail",
            "data" => ["message" => $e->getMessage()]
        ]));
    }

    return $response;
});

$app->get('/books_authors/view', function (Request $request, Response $response, array $args){

    // Database connection
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Prepare SQL query to fetch book-author relationships with book titles and author names
        $stmt = $conn->prepare("
            SELECT books.bookid, books.title, authors.authorid, authors.name
            FROM books
            INNER JOIN books_authors ON books.bookid = books_authors.bookid
            INNER JOIN authors ON authors.authorid = books_authors.authorid
        ");

        // Execute the query
        $stmt->execute();

        // Fetch all results
        $relationships = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Check if any relationships exist
        if ($relationships) {
            // Return success response with the list of relationships
            $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => $relationships
            ]));
        } else {
            // Return response indicating no relationships found
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["message" => "No relationships found."]
            ]));
        }
    } catch (Exception $e) {
        // Handle any exceptions such as database errors
        $response->getBody()->write(json_encode([
            "status" => "fail",
            "data" => ["message" => $e->getMessage()]
        ]));
    }

    return $response;
});

//book-author related endpoint end//

$app->run();

?>
