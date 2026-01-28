<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\ExpiredException;

class JsonWebTokenController extends Controller {
        public static function decode_jwt_valid($jwt_token)
    {
        $secretKey = "2zX!8fD@qY6k#eT^mP9w$Jr1&uV5g*Bf3";
        $allowed_algs = ['HS256'];
        $currentTime = time();

        if (empty($jwt_token)) {
            \Log::error("JWT Token is empty");
            return false;
        }

        // Check if token has 3 segments
        $segments = explode('.', $jwt_token);
        if (count($segments) !== 3) {
            \Log::error("Invalid JWT Token format. Expected 3 segments, got " . count($segments));
            return false;
        }

        if ($jwt_token == null || !isset($jwt_token)) {
            return false;
        }

        try {
            // This single call performs three checks:
            // 1. Decodes the token.
            // 2. Verifies the signature using the secret key.
            // 3. Verifies the expiration (exp), not before (nbf), and issued at (iat) claims.

            $decoded = JWT::decode(
                $jwt_token,
                new Key($secretKey, $allowed_algs[0]) // Pass the key and the algorithm
            );

            // If decoding succeeds without exceptions, the token is valid.
            return $decoded;
        } catch (ExpiredException $e) {
            \Log::error("JWT Expired: " . $e->getMessage());
            return null;
        } catch (SignatureInvalidException $e) {
            \Log::error("JWT Signature Invalid: " . $e->getMessage());
            return null;
        } catch (Exception $e) {
            \Log::error("JWT Decode Error: " . $e->getMessage());
            return null;
        }
    }

    public static function encode_jwt($payload) {
        $allowed_algs = 'HS256';

        $secretKey = "2zX!8fD@qY6k#eT^mP9w$Jr1&uV5g*Bf3";
        $token = JWT::encode($payload, $secretKey, $allowed_algs);

        return $token;
    }
}

?>
