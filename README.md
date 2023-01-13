# Single Sign-On Workflow

![sso_flow](https://user-images.githubusercontent.com/42746403/212332829-dcd442be-e336-479f-ac7a-a1db867d6a8c.jpg)

1. The user accesses to application. 

2. Application finds that the user is not logged in and jumps to the ```sso-server```.

3. The SSO authentication server finds that the user is not logged in and directs the user to the login page.

* We check if the URL that has came as query to the ```sso-server``` has been registered or not.

```
const alloweOrigin = {
  "http://localhost:3000": true,
  "http://localhost:3002": true,
};
```

4. User enters username and password to submit login request.

5. The Authentication server verifies the user information and creates a session (Global session) between the user and the Authentication server. And then creates an Authorization token as well.

6. Then the Authentication server takes the authorization token to redirect to the ```redirect_utl``` along with the ```Authorization token```.

7. The ```sso-client``` gets the token and goes to the ```sso-server``` authentication to check if the token to find out whether the token valid, exists or expires. 
Then the ```sso_server``` return a signed JWT with user information (```Access token```) to the ```sso-client```.

