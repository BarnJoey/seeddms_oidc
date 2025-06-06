# SeedDMS OIDC extension

Extension enables OIDC login for SeedDMS
this is a modification of this extension here:

https://sourceforge.net/projects/seeddms-oidc/

the original extension didn't implement the OIDC protocol properly and didn't work in Authelia. I borrowed a few snippets from this repo to get it working:

https://github.com/jumbojett/OpenID-Connect-PHP

this implementation is still pretty rough but it atleast works.

# Install
first off make sure you have the cUrl PHP extension installed

```
apt install php-curl
```

then copy the oidc extension into your seeddms/www/ext/ directory

# Setup
in your OIDC provider generate a client ID and secret, the redirect url should point to index.php. the ".well-known/callback" directory isn't used in this implementation and no apache / nginx rewrite rules are needed

here's an example config for Authelia:
```
##
##      SeedDMS
##
      - client_id: 'seeddms' # generate a different clientid
        client_name: 'SeedDMS'
        client_secret: '$pbkdf2-sha512$310000$c8p78n7pUMln0jzvd4aK4Q$JNRBzwAo0ek5qKn50cFzzvE9RXV88h1wJn5KGiHrD0YKtZaR/nCb2CJPOsKaPK0hjf.9yHxzQGZziziccp6Yng'  # The digest of 'insecure_secret'.
        public: false
        authorization_policy: 'two_factor'
        redirect_uris:
          - 'http://seeddms.example.com/index.php'
        scopes:
          - 'openid'
          - 'profile'
          - 'groups'
          - 'email'
        userinfo_signed_response_alg: 'none'
        token_endpoint_auth_method: 'client_secret_post'
```

open SeedDMS, navigate to Admin Tools -> Extensions and refresh the list to make sure OIDC appears and comes online
then navigate to Admin Tools -> Settings -> Extensions and configure the OIDC settings as follows

<img src="https://github.com/user-attachments/assets/965ec358-3dd9-49a1-abac-90f86083ab6f" width=75%>

this will get you logged in. refer to the original OIDC extension for configuring role / group mappings. 
