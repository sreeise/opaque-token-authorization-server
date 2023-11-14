## Spring Security 6 JWT Token Authorization Server Example

* Client Credentials used to authorize a REST API for provided scopes.
* Endpoints protected through Basic Auth using client-id and client-secret used to get Bearer Token.
* Use in conjunction with Spring Security Resource Server.
* [See the resource server example that works with this authorization server.](https://github.com/sreeise/opaque-token-resource-server)

Get the bearer token using the authorization server.


    curl -X POST messaging-client:secret@localhost:9000/oauth2/token -d "grant_type=client_credentials" -d "scope=message:read"


Use the introspection endpoint to decode the JWT and verify the token which is also typically done by resource-server.

    curl -X POST messaging-client:secret@localhost:9000/oauth2/introspect -d "token=$TOKEN"


Use the bearer token in the request to the messages endpoints in the resource server:

    export TOKEN="token"

    curl --location --request GET 'http://localhost:8080/message' \
        --header 'Authorization: Bearer $TOKEN'


Credit goes to [Spring Samples Repository](https://github.com/spring-projects/spring-security-samples/tree/main/servlet/spring-boot/java/oauth2/authorization-server) 
and their examples of authorization/resource servers.

This is a minimal version of using opaque tokens that was built from those samples.
