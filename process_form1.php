<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/mailer_config.php'; // SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_PORT
session_start();
header('Content-Type: application/json');

/* ---- 0. Security Layer ---- */

/* --- CSRF token check --- */
if (!isset($_POST['_token']) || !hash_equals($_SESSION['_token'] ?? '', $_POST['_token'])) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Invalid request. Please refresh the page.']);
    exit;
}

/* --- Rate-limit 30 s per IP (simple) --- */
$limiterKey = 'ip_' . $_SERVER['REMOTE_ADDR'];
if (isset($_SESSION[$limiterKey]) && (time() - $_SESSION[$limiterKey]) < 30) {
    http_response_code(429);
    echo json_encode(['success' => false, 'message' => 'Please wait 30sec before submitting again.']);
    exit;
}
$_SESSION[$limiterKey] = time();

/* 1. CAPTCHA Validation (SERVER-SIDE) */
$userCaptcha = strtoupper(trim($_POST['captcha'] ?? ''));
$expectedCaptcha = strtoupper(trim($_SESSION['captcha'] ?? ''));

if (empty($userCaptcha) || empty($expectedCaptcha) || $userCaptcha !== $expectedCaptcha) {
    echo json_encode(['success' => false, 'message' => 'Wrong CAPTCHA. Please try again.']);
    // We don't unset the session captcha here, so they can retry.
    exit;
}

/* 2. Sanitize & validate (field-by-field) */
function sanitize($x) {
    return htmlspecialchars(strip_tags(trim($x)), ENT_QUOTES, 'UTF-8');
}

$name     = sanitize($_POST['name']    ?? '');
$email    = sanitize($_POST['email']   ?? '');
$phone    = sanitize($_POST['phone']   ?? '');
$service  = sanitize($_POST['transport'] ?? $_POST['service'] ?? ''); // Handles both quote and contact forms
$message  = sanitize($_POST['message'] ?? '');
$formType = sanitize($_POST['form_type'] ?? 'unknown');

// Basic email validation
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success' => false, 'message' => 'Invalid email address.']);
    exit;
}

/* --- Validation for required fields --- */
$required = [];
if ($formType === 'quote' || $formType === 'contact') {
    $required = ['name' => $name, 'email' => $email, 'phone' => $phone, 'service' => $service];
} elseif ($formType === 'career') {
    $required = ['name' => $name, 'email' => $email];
}

foreach ($required as $key => $value) {
    if (empty($value)) {
        echo json_encode(['success' => false, 'message' => ucfirst($key) . ' is a required field.']);
        exit;
    }
}

/* 3. Send e-mail */
$mail = new PHPMailer(true);
try {
    $mail->isSMTP();
    $mail->Host       = SMTP_HOST;
    $mail->SMTPAuth   = true;
    $mail->Username   = SMTP_USER;
    $mail->Password   = SMTP_PASS;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
    $mail->Port       = SMTP_PORT;

    $mail->setFrom(SMTP_USER, 'NAME Website');
    $mail->addAddress('Your Email address where you want to send mail');
    //$mail->addAddress('Your Email address where you want to send mail');
    //$mail->addAddress('Your Email address where you want to send mail');
    //$mail->addAddress('Your Email address where you want to send mail');
    $mail->addReplyTo($email, $name);
    
    $mail->isHTML(true);
    $mail->Subject = "New {$formType} submission from your website";
    $body = "<h2>New " . ucfirst($formType) . " Request</h2>
             <p><strong>Name:</strong> {$name}</p>
             <p><strong>Email:</strong> {$email}</p>";
    if(!empty($phone)) $body .= "<p><strong>Phone:</strong> {$phone}</p>";
    if(!empty($service)) $body .= "<p><strong>Service:</strong> {$service}</p>";
    if(!empty($message)) $body .= "<p><strong>Message:</strong><br>" . nl2br($message) . "</p>";
    $mail->Body = $body;

    if ($formType === 'career' && isset($_FILES['resume']) && $_FILES['resume']['error'] === UPLOAD_ERR_OK) {
        // File validation from your original code was good
        $allowed = ['pdf', 'doc', 'docx'];
        $ext = strtolower(pathinfo($_FILES['resume']['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, $allowed)) throw new Exception('Invalid file type.');
        if ($_FILES['resume']['size'] > 5 * 1024 * 1024) throw new Exception('File too large (Max 5MB).');
        
        $mail->addAttachment($_FILES['resume']['tmp_name'], $_FILES['resume']['name']);
    }

    $mail->send();
    // Clear session variables on success
    unset($_SESSION['captcha']);
    unset($_SESSION[$limiterKey]);
    echo json_encode(['success' => true, 'message' => 'Thank you! Your message has been sent.']);

} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => "Message could not be sent. Mailer Error: {$mail->ErrorInfo}"]);
}

?>