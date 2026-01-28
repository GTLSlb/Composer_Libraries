<?php

namespace gtls\loginstory;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Laravel\Socialite\Facades\Socialite;
use Carbon\Carbon\Exception;
use App\Http\Controllers\Auth\JsonWebTokenController;

final class LoginClass
{
    /**
     * Handle a login request to the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */

    public static function login(Request $request)
    {
        $parameters = request()->all();
        $sessionDomain = $parameters['SessionDomain'] ?? '/';
        $userObjectDecode = is_string($parameters['UserObject']) ? json_decode($parameters['UserObject'], true) : $parameters['UserObject'];
        $userObject = is_array($userObjectDecode) ? $userObjectDecode : [$userObjectDecode]; // Check if the decoded value is an array or a json
        $token = $parameters['Token'];

        // Get an array of all the cookies
        $cookies = $_COOKIE;

        // Loop through each cookie and set it to expire
        foreach ($cookies as $name => $value) {
            setcookie($name, '', 1, '/', $sessionDomain, true);
        }

        if ($userObject != null && $token != null) {
            // Generate Token using user id and owner id
            $userId = $userObject['UserId'];
            $request->session()->regenerate();
            $request->session()->put('token', $token);
            $request->session()->put('user', is_array($userObject) ? json_encode($userObject) : $userObject);
            $request->session()->put('user_id', $userId);
            $request->session()->put('newRoute', '/loginapi');

            $sessionId = $request->session()->getId();
            $user = json_encode($userObject);

            $lastActivity = time();
            DB::table('custom_sessions')->insert([
                'id' => $sessionId,
                'user_id' => $userId,
                'payload' => $token,
                'user' => $user,
                'last_activity' => $lastActivity,
                'created_at' => \Carbon\Carbon::now(),
                'updated_at' => \Carbon\Carbon::now(),
            ]);


            $request->session()->save();
            if ($request->session()->get('newRoute') && $request->session()->get('user')) {
                return json_encode(['user' => $user, 'token' => $token, 'request' => $request, 'status' => 200, 'message' => 'Login successful']);
            }
        } else {
            $errorMessage = 'Something went wrong, try again later';
            $statusCode = 500;
            return json_encode(['user' => null, 'token' => null, 'request' => $request, 'status' => $statusCode, 'message' => $errorMessage]);
        }
    }

    public function logout(Request $request)
    {
        $parameters = request()->all();
        $sessionDomain = $parameters['SessionDomain'] ?? '';
        $user = $parameters['CurrentUser'];
        $url = $parameters['URL'];

        // Retrieve the 'access_token' cookie if available
        // $token = $_COOKIE['access_token'] ?? null;

        $stringifiedUser = json_encode($user);
        // Create an instance of the RegisteredUserController and get the current user
        $userMsg = json_decode($stringifiedUser, true);

        // If user data indicates 'User not found'
        if (isset($userMsg['message']) && $userMsg['message'] === 'User not found') {
            // Invalidate and flush session data
            $request->session()->invalidate();
            $request->session()->flush();

            // Clear cookies to log the user out fully
            $this->clearAllCookies($sessionDomain);

            // Regenerate the session token for security purposes
            $request->session()->regenerateToken();

            // Respond with success (Azure AD logout will be handled on the frontend)
            return json_encode(['status' => 200, 'message' => 'Logged out locally successfully']);
        } else {
            // If user is found, proceed with API logout
            $UserId = $user['UserId'];

            // Set up headers for the API request
            $headers = [
                'UserId' => $UserId,
                // 'Authorization' => "Bearer " . $token,
            ];

            // Send the logout request to the external API
            $response = Http::withHeaders($headers)->get($url . "Logout");

            // Check if the logout request was successful
            if ($response->successful()) {

                // Invalidate and flush session data
                session()->forget('user');
                session()->invalidate();
                session()->flush();

                // Clear cookies to log the user out fully
                $this->clearAllCookies($sessionDomain);

                // Regenerate the session token for security purposes
                $request->session()->regenerateToken();

                // Respond with success (Azure AD logout will be handled on the frontend)
                return json_encode(['status' => 200, 'message' => 'Logged out successfully']);
            } else {
                // Handle failure in the external API call
                return json_encode(['status' => 500, 'message' => 'Logout failed. Please try again.']);
            }
        }
    }

    /**
     * Helper function to clear all cookies.
     */
    private function clearAllCookies($sessionDomain)
    {
        // Set the expiration time for the cookies to a past date (January 1, 1970)
        $expiration = time() - 3600;

        // Set domain and flags for cookie clearing
        $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';

        // Loop through each cookie and set it to expire
        foreach ($_COOKIE as $name => $value) {
            // Clear the cookie for all paths and domains
            setcookie($name, '', $expiration, '/', $sessionDomain, $secure, true); // Secure and HttpOnly flags
        }
    }

    public function logoutWithoutRequest(Request $request)
    {
        // $parameters = request()->all();
        // $sessionDomain = $parameters['SessionDomain'] ?? '/';

        try {
            //check if user is found
            if ($request->session()->has('user')) {
                //Remove user and from session
                $request->session()->forget('user');
            }

            //check if token is found
            if ($request->session()->has('token')) {
                //Remove token from session
                $request->session()->forget('token');
            }

            // Invalidate and flush the session
            $request->session()->invalidate();
            $request->session()->flush();

            // Regenerate the session token
            $request->session()->regenerateToken();

            return \Illuminate\Support\Facades\Response::json([
                'message' => 'Logout Successfully',
            ], 200);
        } catch (\Exception $e) {

            return \Illuminate\Support\Facades\Response::json([
                'message' => 'Logout failed. Please try again. ' . $e->getMessage(),
            ], 500);
        }
    }

    public function handleCallback(Request $request)
    {
        $parameters = request()->all();
        $redirectRoute = $parameters['RedirectRoute'] ?? '/';
        $gtamUrl = $parameters['URL'] ?? '/';

        if (\Illuminate\Support\Facades\Session::has('user')) {
            return \Illuminate\Support\Facades\Redirect::route($redirectRoute);  // Redirect if session exists
        }

        // Proceed with the login flow if the session does not exist
        try {
            $socialiteUser = Socialite::driver('azure')->user();
            $accessToken = $socialiteUser->token;
            $expiresIn = $socialiteUser->expiresIn;

            // Send request to external API for validation
            $headers = ['Authorization' => $accessToken];

            $response = Http::withHeaders($headers)->get($gtamUrl . "validate/MicrosoftToken");

            if ($response->successful()) {
                $responseJson = $response->json();

                \Illuminate\Support\Facades\Session::regenerate();
                \Illuminate\Support\Facades\Session::put('user', $responseJson);
                \Illuminate\Support\Facades\Session::put('user_id', $responseJson['UserId']);
                \Illuminate\Support\Facades\Session::put('newRoute', \Illuminate\Support\Facades\Route::route('azurelogin'));

                // Insert into custom_sessions
                DB::table('custom_sessions')->insert([
                    'id' => \Illuminate\Support\Facades\Session::getId(),
                    'user_id' => $responseJson['UserId'],
                    'payload' => \Illuminate\Support\Facades\Session::get('_token'),
                    'user' => json_encode($responseJson),
                    'last_activity' => time(),
                    'created_at' => \Carbon\Carbon::now(),
                    'updated_at' => \Carbon\Carbon::now(),
                ]);

                // Encode the user data
                $payload = [
                    'user' => is_array($userObject) ? json_encode($userObject) : $userObject,
                    'Token' => $token,
                    'userId' => $userId
                ];

                $new_jwt = JsonWebTokenController::encode_jwt($payload);
                return \Illuminate\Support\Facades\Response::json([
                    'message' => 'Login successful',
                    'access_token' => $accessToken,
                    'expires_in' => $expiresIn,
                    'user' => is_array($userObject) ? json_encode($userObject) : $userObject,
                    'jwt_token' => $new_jwt,
                ]);
            }
        } catch (\Exception $e) {
            return \Illuminate\Support\Facades\Response::json([
                'message' => 'Authentication error: ' . $e->getMessage(),
            ], 500);
        }
    }


    public function sendToken(Request $request)
    {
        $parameters = request()->all();
        $accessToken = $request->socialiteUser['accessToken'];
        $expiresIn = $request->socialiteUser['expiresOn'];
        $gtamUrl = $parameters['URL'] ?? '/';

        // find the user in the database through API
        $url = $gtamUrl . "validate/MicrosoftToken";

        $headers = [
            'Authorization' => $accessToken,
        ];

        // Send the logout request to the external API
        $response = Http::withHeaders($headers)->post($url);


        if ($response->successful()) {
            $responseJson = $response->json();

            $userObject = $responseJson['user'];
            $token = $responseJson['access_token'];
            $userId = $userObject['UserId'];

            $request->session()->regenerate();
            $request->session()->put('token', $token);
            $request->session()->put('user', is_array($userObject) ? json_encode($userObject) : $userObject);
            $request->session()->put('user_id', $userId);
            $request->session()->put('newRoute',  value: route('azure.login'));

            $sessionId = $request->session()->getId();
            $lastActivity = time();

            DB::table('custom_sessions')->insert([
                'id' => $sessionId,
                'user_id' => $userId,
                'payload' => $token,
                'user' => is_array($userObject) ? json_encode($userObject) : $userObject,
                'last_activity' => $lastActivity,
                'created_at' => \Carbon\Carbon::now(),
                'updated_at' => \Carbon\Carbon::now(),
            ]);
            $request->session()->save();

            // Encode the user data
            $payload = [
                'user' => is_array($userObject) ? json_encode($userObject) : $userObject,
                'Token' => $token,
                'userId' => $userId
            ];

            $new_jwt = JsonWebTokenController::encode_jwt($payload);
            return \Illuminate\Support\Facades\Response::json([
                'message' => 'Login successful',
                'access_token' => $accessToken,
                'expires_in' => $expiresIn,
                'user' => is_array($userObject) ? json_encode($userObject) : $userObject,
                'jwt_token' => $new_jwt,
            ]);
        } else {
            if (str_contains($response->json()['Message'], 'Error while validating token: Code: InvalidAuthenticationToken')) {
                return \Illuminate\Support\Facades\Response::json([
                    'Message' =>  'Error while validating token: Invalid Authentication Token',
                    'error' =>  $response->json(),
                ], 500);
            } else {
                return \Illuminate\Support\Facades\Response::json([
                    'Message' =>  $response->json()['Message'] ?? 'Authentication error',
                    'error' =>  $response->json(),
                ], 500);
            }
        }
    }
}
