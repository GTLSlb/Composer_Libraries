# Gold Tiger Login Functions

Login and Logout Story using credentials and Microsoft API

## Table of Contents

*Login with credentials parameters:*

- URL: URL of the API
- SessionDomain: Domain of the website
- Email: Email of the user
- Password: Password of the user
  
*Logout parameters:*

- URL: URL of the API
- SessionDomain: Domain of the website
- CurrentUser: Current user object

*logoutWithoutRequest parameters:*

- SessionDomain: Domain of the website
- CurrentUser: Current user object

*Handle Microsoft Callback parameters:*

- URL: URL of the API
- RedirectRoute: Route to redirect to after login if there is a user in the session

*Send Access Token to API parameters:*

- URL: URL of the API
- socialiteUser: Socialite user object obtained from Microsoft Login
