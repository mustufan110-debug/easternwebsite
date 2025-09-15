<?php
// get_captcha.php
session_start();
header('Content-Type: application/json');

$chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
$captcha_string = '';
for ($i = 0; $i < 6; $i++) {
    $captcha_string .= $chars[rand(0, strlen($chars) - 1)];
}

// Store the correct CAPTCHA in the session
$_SESSION['captcha'] = $captcha_string;

// Send the string to the JavaScript
echo json_encode(['captcha' => $captcha_string]);
?>