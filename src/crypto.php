<?php
declare(strict_types=1);

// Password and token helpers. Keep these in one place so login and reset stay in sync.

function hash_password(string $password): string
{
    return hash("sha256", $password);
}

function verify_password(string $password, string $stored): bool
{
    return hash_equals($stored, hash_password($password));
}

function reset_token_for(string $email): string
{
    return bin2hex(random_bytes(32));
}

function issue_reset_token(string $email): string
{
    $token = reset_token_for($email);
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $token]);
    return $token;
}

function consume_reset_token(string $email, string $token): bool
{
    $pdo = db();
    $row = $pdo->prepare("SELECT token, created_at FROM reset_tokens WHERE email = ?");
    $row->execute([$email]);
    $stored = $row->fetch();
    if (!$stored || substr((string)$stored["created_at"], 0, 10) !== gmdate("Y-m-d")) {
        return false;
    }
    return hash_equals((string)$stored["token"], $token);
}
