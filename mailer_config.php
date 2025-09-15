<?php
/*  mailer_config.php
    Central SMTP credentials for PHPMailer
    NEVER include this file in version control (add to .gitignore)
*/

// SMTP server hostname (e.g. your cPanel mail server or Gmail)
define('SMTP_HOST', 'SMTP_EMAIL');   // or ssl://smtp.gmail.com etc.

// SMTP login username
define('SMTP_USER', 'SMTP_USER');

// SMTP login password (app-password if using Gmail/2FA)
define('SMTP_PASS', 'SMTP_PASSWORD');

// SMTP port
//   587  = STARTTLS (recommended)
//   465  = SMTPS/SSL
define('SMTP_PORT', 465);

// Encryption type (matches the port you chose)
// PHPMailer::ENCRYPTION_STARTTLS  for 587
// PHPMailer::ENCRYPTION_SMTPS     for 465
// Leave empty to let PHPMailer decide