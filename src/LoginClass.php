<?php

namespace gtls\loginstory;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Laravel\Socialite\Facades\Socialite;
use Carbon\Carbon\Exception;

final class LoginClass
{
    /**
     * Handle a login request to the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public static function index()
    {
        $data = (['status' => 200, 'message' => 'Logged in locally. Handle Azure AD login on frontend.']);
        return json_encode($data);
    }

    public static function login(Request $request)
    {
        $parameters = request()->all();
        $sessionDomain = $parameters['SessionDomain'] ?? '/';
        $email = $parameters['Email'];
        $password = $parameters['Password'];
        $url = $parameters['URL'];

        $headers = [
            'Email' => $email,
            'Password' => $password,
        ];

        // Get an array of all the cookies
        $cookies = $_COOKIE;

        // Loop through each cookie and set it to expire
        foreach ($cookies as $name => $value) {
            setcookie($name, '', 1, '/', $sessionDomain, true);
        }
        $response = Http::withHeaders($headers)->get("$url" . "Login");
        if ($response->successful()) {
            $responseData = $response->json();
            if (!empty($responseData)) {
                // $authProvider = new CustomAuth();

                $credentials = [
                    'EmailInput' => $request->input('Email'),
                    'EmailDb' => $responseData[0]['Username'],
                    'PasswordDb' => $responseData[0]['UserId'],
                    'PasswordInput' => $request->input('Password'),
                ];

                // Generate Token using user id and owner id
                $user = null;
                $TokenHeaders = [
                    'UserId' => $responseData[0]['UserId'],
                    'OwnerId' => $responseData[0]['OwnerId'],
                    // 'AppId'=> $appID,
                    'Content-Type' => "application/x-www-form-urlencoded",
                ];
                $TokenBody = [
                    'grant_type' => "password",
                ];

                $tokenURL = $url;
                $tokenRes = Http::withHeaders($TokenHeaders)
                    ->asForm()
                    ->post("$tokenURL" . "Token", $TokenBody);

                $user = $responseData[0];

                if ($tokenRes->successful()) {
                    $token = $tokenRes->json();
                    $cookieName = 'access_token';
                    $cookieValue = $token['access_token'];
                    setcookie($cookieName, $cookieValue, 1, '/', $sessionDomain, true);
                    $userId = $user['UserId'];
                    $request->session()->regenerate();
                    $request->session()->put('user', $user);
                    $request->session()->put('user_id', $userId);
                    $request->session()->put('newRoute', '/loginapi');

                    $sessionId = $request->session()->getId();
                    $payload = $request->session()->get('_token');
                    $userSession = $request->session()->get('user');
                    $user = json_encode($userSession);

                    $lastActivity = time();
                    DB::table('custom_sessions')->insert([
                        'id' => $sessionId,
                        'user_id' => $userId,
                        'payload' => $payload,
                        'user' => $user,
                        'last_activity' => $lastActivity,
                        'created_at' => date("Y-m-d H:i:s"),
                        'updated_at' => date("Y-m-d H:i:s"),
                    ]);


                    $request->session()->save();
                    if ($request->session()->get('newRoute') && $request->session()->get('user')) {
                        return json_encode(['user' => $user, 'request' => $request, 'status' => 200, 'message' => 'Login successful']);
                    }
                } else {
                    $errorMessage = 'Something went wrong, try again later';
                    $statusCode = 500;
                    return json_encode(['user' => null, 'request' => $request, 'status' => $statusCode, 'message' => $errorMessage]);
                }
            }
        } else {
            $errorMessage = 'Invalid Credentials';
            $statusCode = 500;
            return json_encode(['user' => null, 'request' => $request, 'status' => $statusCode, 'message' => $errorMessage]);
        }
    }

    public function logout(Request $request)
    {
        $parameters = request()->all();
        $sessionDomain = $parameters['SessionDomain'] ?? '';
        $user = $parameters['CurrentUser'];
        $url = $parameters['URL'];

        // Retrieve the 'access_token' cookie if available
        $token = $_COOKIE['access_token'] ?? null;

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
                'Authorization' => "Bearer " . $token,
            ];

            // Send the logout request to the external API
            $response = Http::withHeaders($headers)->get($url . "Logout");

            // Check if the logout request was successful
            if ($response->successful()) {

                // Invalidate and flush session data
                $request->session()->forget('user');
                $request->session()->invalidate();
                $request->session()->flush();

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
        $parameters = request()->all();
        $sessionDomain = $parameters['SessionDomain'] ?? '/';

        try{

        // Invalidate and flush the session
        $request->session()->invalidate();
        $request->session()->flush();

        // Regenerate the session token
        $request->session()->regenerateToken();

        // Set the expiration time for the cookies to a past date (January 1, 1970)
        $expiration = time() - 3600;
        $cookies = $_COOKIE;

        $_COOKIE['access_token'] = '';
        // Loop through each cookie and set it to expire
        foreach ($cookies as $name => $value) {
            setcookie($name, '', $expiration, '/', $sessionDomain, true);
        }

        //check if user is not found
        if ($request->session()->has('user')) {
            //Remove user from session
            $request->session()->forget('user');
        }

        return response()->json([
            'message' => 'Logout Successfully',
        ], 200);

        }catch(\Exception $e){

            return response()->json([
                'message' => 'Logout failed. Please try again. ' . $e->getMessage(),
            ], 500);
        }
    }

    public function handleCallback(Request $request)
    {
        $parameters = request()->all();
        $redirectRoute = $parameters['RedirectRoute'] ?? '/';
        $gtamUrl = $parameters['URL'] ?? '/';

        if (session()->has('user')) {
            return redirect()->route($redirectRoute);  // Redirect if session exists
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
                session()->regenerate();
                session()->put('user', $responseJson);
                session()->put('user_id', $responseJson['UserId']);
                session()->put('newRoute', route('azurelogin'));

                // Insert into custom_sessions
                DB::table('custom_sessions')->insert([
                    'id' => session()->getId(),
                    'user_id' => $responseJson['UserId'],
                    'payload' => session()->get('_token'),
                    'user' => json_encode($responseJson),
                    'last_activity' => time(),
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);

                return response()->json([
                    'message' => 'Login successful',
                    'access_token' => $accessToken,
                    'expires_in' => $expiresIn,
                    'user' => $responseJson,
                ]);
            }
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Authentication error: ' . $e->getMessage(),
            ], 500);
        }
    }


    public function sendToken(Request $request){
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
            // $responseBody = $response->body();
            $responseJson = $response->json();

            $jsonString = json_encode($responseJson);

            $request->session()->regenerate();
            $request->session()->put('user', json_encode($responseJson[0]));
            $request->session()->put('user_id', $responseJson[0]['UserId']);
            $request->session()->put('newRoute', route('azure.login'));

            $sessionId = $request->session()->getId();
            $payload = $request->session()->get('_token');
            $userSession = $request->session()->get('user');
            $user = $jsonString;
            $lastActivity = time();

            DB::table('custom_sessions')->insert([
                'id' => $sessionId,
                'user_id' => $responseJson[0]['UserId'],
                'payload' => $payload,
                'user' => $userSession,
                'last_activity' => $lastActivity,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            $request->session()->save();

            return response()->json([
                'message' => 'Login successful',
                'access_token' => $accessToken,
                'expires_in' => $expiresIn,
                'user' => $user,
            ]);
        } else {
            if(str_contains($response->json()['Message'], 'Error while validating token: Code: InvalidAuthenticationToken')) {
                return response()->json([
                    'Message' =>  'Error while validating token: Invalid Authentication Token',
                    'error' =>  $response->json(),
                ], 500);
            }else{
                return response()->json([
                    'Message' =>  $response->json()['Message'] ?? 'Authentication error',
                    'error' =>  $response->json(),
                ], 500);
            }
        }
    }
}
