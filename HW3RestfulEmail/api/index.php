<?php

session_cache_limiter(false);
session_start();

require_once '../vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// create a log channel
$log = new Logger('main');
$log->pushHandler(new StreamHandler('../logs/main.log', Logger::DEBUG));
$log->pushHandler(new StreamHandler('../logs/main.log', Logger::ERROR));

// http://meekro.com/
DB::$dbName = 'HW3RestfulEmail';
DB::$user = 'HW3RestfulEmail';
DB::$password = 'YxYa7GSKHP69GSNY';
DB::$encoding = 'utf8'; // defaults to latin1

DB::$error_handler = 'sql_error_handler';
DB::$nonsql_error_handler = 'nonsql_error_handler';

function nonsql_error_handler($params) {
    global $app, $log;
    $log->error("Database error: " . $params['error']);
    http_response_code(500);
    echo '"500 - internal error"';
    die;
}

function sql_error_handler($params) {
    global $app, $log;
    $log->error("SQL error: " . $params['error']);
    $log->error(" in query: " . $params['query']);
    http_response_code(500);
    echo '"500 - internal error"';
    die; // don't want to keep going if a query broke
}

$app = new \Slim\Slim();

\Slim\Route::setDefaultConditions(array (
    'id' => '\d+'
));

$app->response->headers->set('content-type', 'application/json');

function getAuthUserId() {
    global $app, $log;
    $email = $app->request->headers("PHP_AUTH_USER");
    $password = $app->request->headers("PHP_AUTH_PW");
    if ($email && $password) {
        $row = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $email);
        if ($row && $row['password'] == $password) {
            return $row['ID'];
        }
    }
    $log->debug("BASIC authentication failed for email " . $email .
            " from " . $_SERVER['REMOTE_ADDR']);
    $app->response->status(401);
    echo json_encode('Unauthorized');
    // $app->response->header("WWW-Authenticate", "Basic realm=TodoApp API");
    return FALSE;
}

$app->get('/register.html', function () use ($app) {
    $app->response->headers->set('content-type', 'text/html');
    echo file_get_contents('../register.html');
});

$app->get('/mail.html', function () use ($app) {
    $app->response->headers->set('content-type', 'text/html');
    echo file_get_contents('../mail.html');
});

// & means output parameter
function isUserValid($user, &$error, $skipID = FALSE) {
    
    // Check if user with that email already exists
    $email = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $user['loginEmail']);
    if ($email) {
        $error = "E-mail already exists";
        return;
    }
    // Check if email address does not look like a valid email
    if (!filter_var($user['loginEmail'], FILTER_VALIDATE_EMAIL)) {
        $error = "E-mail is not valid";
        return;
    }
    // Check if fullName is shorter than 2 characters
    if (strlen($user['fullName']) < 2 || strlen($user['fullName']) > 50) {
        $error = "Full name must be at least 2 characters long";
        return;
    }
    // Check if passwords match
    if ($user['password'] !== $user['passwordReapeted']) {
        $error = "Passwords do not match";
        return;
    }
    // Check if password too weak (must be at least 8 characters, at least one uppercase, one lowercase, one number or special character)
    if (!preg_match("/(?=.*[a-z])(?=.*[A-Z])((?=.*\d)|(?=.*[$@$!%*?&]))[A-Za-z\d$@$!%*?&]{8,100}/" ,$user['password'])) {
        //$error = "Password must be between 8 and 100 characters, at least one uppercase, one lowercase, one number or special character";
        $error = "Password too weak";
        return;
    } 
    return true;
}

// POST /api/v1/users
// do not require HTTP BASIC authentication
// Used to create a new user
$app->post('/api/v1/users', function() use ($app, $log) {
    $body = $app->request->getBody();
    $user = json_decode($body, TRUE);
    if (!isUserValid($user, $error)) {
        $app->response()->setStatus(400);
        $log->debug("POST /api/v1/users [[" . $body . "]] data invalid: " . $error);
        echo json_encode($error);
        return;
    }
    $dataToInsert = array();
    $dataToInsert['email'] = $user['loginEmail'];
    $dataToInsert['fullName'] = $user['fullName'];
    $dataToInsert['password'] = $user['password'];
    // Creates user
    DB::insert('users', $dataToInsert);
    if (DB::insertId()) {
        $log->debug("POST /api/v1/users [[" . $body . "]] user created");
        $app->response->setStatus(201);
        echo json_encode(true);
    }
});

 
// PUT /api/v1/users/user@server.com
$app->put('/api/v1/users/:email', function($email) use ($app, $log) {
    $userId = getAuthUserId();
    if (!$userId) {
        return;
    }
    $body = $app->request->getBody();
    $user = json_decode($body, TRUE);
    
    // Check if user with that email already exists
    $result = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $user['loginEmail']);
    if (!$result) {
        $app->response()->setStatus(400);
        $log->debug("POST /api/v1/users [[" . $body . "]] data invalid: Invalid credentials");
        echo json_encode("Invalid credentials");
        return;
    }
    if ($userId !== $result['ID'] || $email !== $result['email']) {
        $app->response()->setStatus(403);
        $log->debug("POST /api/v1/users [[" . $body . "]] data invalid: Forbidden");
        echo json_encode("Forbidden");
        return;
    }
    if ($user['passwordOld'] !== $result['password']) {
        $app->response()->setStatus(400);
        $log->debug("POST /api/v1/users [[" . $body . "]] data invalid: Invalid credentials");
        echo json_encode("Invalid credentials");
        return;
    }
    if ($user['passwordNew'] !== $user['passwordNewReapeted']) {
        $app->response()->setStatus(400);
        $log->debug("POST /api/v1/users [[" . $body . "]] data invalid: New passwords do not match");
        echo json_encode("New passwords do not match");
        return;        
    }
    if (!preg_match("/(?=.*[a-z])(?=.*[A-Z])((?=.*\d)|(?=.*[$@$!%*?&]))[A-Za-z\d$@$!%*?&]{8,100}/" ,$user['passwordNew'])) { 
        $app->response()->setStatus(400);
        $log->debug("POST /api/v1/users [[" . $body . "]] data invalid: Password too weak");
        //echo json_encode("Password must be between 8 and 100 characters, at least one uppercase, one lowercase, one number or special character");
        echo json_encode("Password too weak");
        return;        
    }
    $dataToUpdate = array();
    $dataToUpdate['email'] = $user['loginEmail'];
    $dataToUpdate['password'] = $user['passwordNew'];
    if (DB::update('users', $dataToUpdate, "email=%s", $user['loginEmail'])) {
        $app->response->setStatus(200);
        echo json_encode(true);
    }
});

// GET /api/v1/users/user@server.com
// This call is used by client only to test whether user credentials are valid
$app->get('/api/v1/users/:email', function($email) use ($app, $log) { 
    $userId = getAuthUserId();
    if (!$userId) {
        return;
    }
    $result = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $email);
    if ($userId !== $result['ID'] || $email !== $result['email']) {
        $app->response()->setStatus(403);
        $log->debug("GET /api/v1/users [[" . $email . "]] data invalid: Forbidden");
        echo json_encode("Forbidden");
        return;
    }
    $user = DB::queryFirstRow("SELECT * FROM users WHERE ID=%i", $userId);
    if ($user) {
        $app->response->setStatus(200);
        echo json_encode(true);
    } else {
        $app->response->setStatus(404);
        echo json_encode("404 – not found");
    }
});

// GET /api/v1/emails/Inbox
// Return list of emails of current user that are in folder 'Inbox'. Other folders are also accessible. 
$app->get('/api/v1/emails/inbox', function() use ($app, $log) {
    $folder = 'Inbox';
    $userId = getAuthUserId();
    if (!$userId) {
        return;
    }
    $folderList = DB::query("SELECT ID, emails.from, subject FROM emails WHERE userID=%i and folder=%s order by dateSent desc", $userId, $folder);
    if ($folderList) {
        $app->response->setStatus(200);
        echo json_encode($folderList, JSON_PRETTY_PRINT);
    }else {
        $app->response->setStatus(404);
        echo json_encode("Not found");
    }
});

$app->get('/api/v1/emails/important', function() use ($app, $log) {
    $folder = 'Important';
    $userId = getAuthUserId();
    if (!$userId) {
        return;
    }
    $folderList = DB::query("SELECT ID, emails.from, subject FROM emails WHERE userID=%i and folder=%s order by dateSent desc", $userId, $folder);
    if ($folderList) {
        $app->response->setStatus(200);
        echo json_encode($folderList, JSON_PRETTY_PRINT);
    }else {
        $app->response->setStatus(404);
        echo json_encode("Not found");
    }
});

$app->get('/api/v1/emails/social', function() use ($app, $log) {
    $folder = 'Social';
    $userId = getAuthUserId();
    if (!$userId) {
        return;
    }
    $folderList = DB::query("SELECT ID, emails.from, subject FROM emails WHERE userID=%i and folder=%s order by dateSent desc", $userId, $folder);
    if ($folderList) {
        $app->response->setStatus(200);
        echo json_encode($folderList, JSON_PRETTY_PRINT);
    }else {
        $app->response->setStatus(404);
        echo json_encode("Not found");
    }
});

$app->get('/api/v1/emails/outbox', function() use ($app, $log) {
    $folder = 'Outbox';
    $userId = getAuthUserId();
    if (!$userId) {
        return;
    }
    $folderList = DB::query("SELECT ID, emails.from, subject FROM emails WHERE userID=%i and folder=%s order by dateSent desc", $userId, $folder);
    if ($folderList) {
        $app->response->setStatus(200);
        echo json_encode($folderList, JSON_PRETTY_PRINT);
    }else {
        $app->response->setStatus(404);
        echo json_encode("Not found");
    }
});

$app->get('/api/v1/emails/spam', function() use ($app, $log) {
    $folder = 'Spam';
    $userId = getAuthUserId();
    if (!$userId) {
        return;
    }
    $folderList = DB::query("SELECT ID, emails.from, subject FROM emails WHERE userID=%i and folder=%s order by dateSent desc", $userId, $folder);
    if ($folderList) {
        $app->response->setStatus(200);
        echo json_encode($folderList, JSON_PRETTY_PRINT);
    }else {
        $app->response->setStatus(404);
        echo json_encode("Not found");
    }
});

// GET /api/v1/emails/56
 $app->get('/api/v1/emails/:emailID', function($emailID) use ($app, $log) {
    $userId = getAuthUserId();
    if (!$userId) {
        return;
    }
    // Checks if the e-mail exists and if it is from the authorized user
    $result = DB::queryFirstRow("SELECT userID FROM emails WHERE ID=%i", $emailID);
    if ($result['userID'] && ($userId !== $result['userID'])) {
        $app->response()->setStatus(403);
        echo json_encode("Forbiden");
        return;
    }
    $email = DB::queryFirstRow("SELECT ID, emails.from, subject, body, attachmentFileName, folder FROM emails WHERE userID=%i and ID=%i", $userId, $emailID);
    $log->debug("GET /api/v1/emails/:emailId" . $email['ID']);
    if (!$email) {
        $app->response()->setStatus(404);
        echo json_encode("Email not found");
        return;
    }
    $app->response()->setStatus(200); 
    echo json_encode($email, JSON_PRETTY_PRINT);
});


// GET /api/v1/emails/12345/attachment?email=jerry&password=abc123
$app->get('/api/v1/emails/:emailID/attachment', function($emailID) use ($app, $log) {
    $email = $app->request()->get('email');
    $password = $app->request()->get('password');
    $log->debug("Download attachment starting. E-mail: " . $email . " Password: " . $password);
    
    
    if ($email && $password) {
        $row = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $email);
        if ($row && $row['password'] == $password) {
            $userID = $row['ID'];
        } else {
            $app->response()->setStatus(401);
            echo json_encode("Unauthorized");
            return;
        }
    }
    $result = DB::queryFirstRow("SELECT userID FROM emails WHERE ID=%s", $emailID);
    if ($result['userID'] !== $userID) {
        $app->response()->setStatus(403);
        echo json_encode("Forbiden");
        return;
    }
            
    $file = DB::queryFirstRow("SELECT attachment, attachmentMimeType, attachmentFileName FROM emails where ID=%i", $emailID);
    if (!$file) {
        $app->response()->setStatus(404);
        echo json_encode("404 - item not found");
        return;
    }
    $attachment = $file['attachment'];
    $attachmentMimeType = $file['attachmentMimeType'];
    $attachmentFileName = $file['attachmentFileName'];
    echo $attachment;
    $app->response->headers->set('Content-Transfer-Encoding', 'binary');
    $app->response->headers->set('Content-Type', $attachmentMimeType);
    $app->response->headers->set('Content-Disposition', 'attachment; filename="' . $attachmentFileName . '"');
    $app->response()->setStatus(200);
});



// POST /api/v1/emails
// Creates new email
 $app->post('/api/v1/emails', function() use ($app, $log) {
    $userId = getAuthUserId();
    if (!$userId) {
        return;
    }
    $body = $app->request->getBody();
    $email = json_decode($body, TRUE);
    $errorList = array();
    if (strlen($email['subject']) < 2 || strlen($email['subject']) > 200) {
        array_push($errorList, "Subject must be between 2 and 200 characters."); 
    }
    if (!filter_var($email['to'], FILTER_VALIDATE_EMAIL)) {
        array_push($errorList, "Invalid e-mail address");
    } elseif (strlen($email['to']) > 200) {
        array_push($errorList, "E-mail must have less than 200 characters");
    }
    if (strlen($email['body']) > 2000) {
        array_push($errorList, "E-mail must have less than 2000 characters");
    }
    if ($errorList) {
        $app->response()->setStatus(400);
        echo json_encode($errorList);
        return;
    }
    $dataToInsert = array();
    $dataToInsert['ID'] = NULL;
    $dataToInsert['userID'] = $userId;
    $dataToInsert['folder'] = 'Outbox';
    $dataToInsert['dateSent'] = DB::sqleval("NOW()");
    $dataToInsert['from'] = $app->request->headers("PHP_AUTH_USER");
    $dataToInsert['to'] = $email['to'];
    $dataToInsert['subject'] = $email['subject'];
    $dataToInsert['body'] = $email['body'];
    if ($email['attachmentFileName']) {
        $dataToInsert['attachment'] = base64_decode($email['attachment']);
        $dataToInsert['attachmentMimeType'] = $email['attachmentMimeType'];
        $dataToInsert['attachmentFileName'] = $email['attachmentFileName'];
    } else {
        $dataToInsert['attachment'] = NULL;
        $dataToInsert['attachmentMimeType'] = NULL;
        $dataToInsert['attachmentFileName'] = NULL;
    }
    DB::insert('emails', $dataToInsert);
    if (DB::insertId()) {
        $app->response->setStatus(201);
        echo json_encode(DB::insertId());
    }
 });



// PUT /api/v1/emails/123
$app->put('/api/v1/emails/:emailID', function($emailID) use ($app, $log) {
    $userId = getAuthUserId();
    if (!$userId) {
        return;
    }
    $body = $app->request->getBody();
    $dataToUpdate = json_decode($body, TRUE);
    $log->debug("PUT: dataToUpdate: " . $dataToUpdate['folder']);
    if (($dataToUpdate['folder'] !== "inbox") && ($dataToUpdate['folder'] !== "important") && ($dataToUpdate['folder'] !== "social") && ($dataToUpdate['folder'] !== "spam")) {
        $app->response->setStatus(400);
        echo json_encode("Invalid folder");
        return;
    }
    $result = DB::queryFirstRow("SELECT userID FROM emails WHERE ID=%i", $emailID);
    if ($result['userID'] && ($userId !== $result['userID'])) {
        $app->response()->setStatus(403);
        echo json_encode("Forbiden");
        return;
    }
    if (DB::update('emails', array('folder' => $dataToUpdate['folder']), "ID=%i AND userId=%i", $emailID, $userId)) { 
        $app->response->setStatus(200);
        echo json_encode(true);
    }
 });
 
 
// GET /api/v1/queue
$app->get('/api/v1/queue', function() use ($app, $log) {
    //$app->response()['Content-Type'] = 'application/json';
    $deliveredCount = 0;
    $undeliveredEmails = array();
    $emailList = DB::query("SELECT ID, emails.to FROM emails WHERE folder='Outbox'");
    $log->debug(print_r($emailList));
    foreach ($emailList as $email) {
        $recipientID = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $email['to']);
        if ($recipientID) {
            // recipient found
            DB::update('emails', array('userID' => $recipientID['ID'], 'folder' => 'Inbox'), "ID=%i", $email['ID']);          
            $deliveredCount++;
        } else {
            // recipient not found
            array_push($undeliveredEmails, $email['to']);
        }
    }
    $retval = array(
        "processed" => count($emailList),
        "delivered" => $deliveredCount,
        "undeliveredList" => $undeliveredEmails
    );
    echo json_encode($retval, JSON_PRETTY_PRINT);
});

$app->run();