privacyidea-ldap-proxy
======================

Current issues:

 * SSL certificate validation is untested
 * Error handling is pretty much untested
 * After an incoming bind request has been successfully authenticated by privacyIDEA,
   the connection is authenticated afterwards, but *as the service user*! This might be some kind of privilege escalation.
   On the other hand, we cannot issue a bind request to the LDAP server using the DN of the incoming bind request,
   because we do not know the corresponding LDAP password.
 * ownCloud sends three LDAP Bind Requests on login. Obviously this causes problems if each bind request is forwarded
   to privacyIDEA. To mitigate the issue, I built a "bind cache": If an incoming bind request has been successfully
   authenticated by privacyIDEA, subsequent bind requests with the same DN and password are accepted *without
   redirecting them to privacyIDEA* for a predefined timeframe (currently 5 seconds); again impersonating
   the service user! Again, this could result in a privilege escalation issue. Also, we might have a
   security issue: During the 5-second window, an attacker could reuse the OTP value, which somewhat
   destroys the advantage of OTP values.
 * While a user is logged in, ownCloud tries to validate the session every five minutes. This includes
   sending another bind request (lib/private/User/Session.php(196))
   We cannot really do anything here.

Tested systems
--------------

 * ownCloud 9.1.3: only works with the bind cache (and even then only for sessions of under 5 minutes)
 * Wordpress 4.4.2 with Simple LDAP Login 1.6.0: seems to work without the bind cache