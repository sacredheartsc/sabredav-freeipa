# sabredav-freeipa

[FreeIPA](https://www.freeipa.org/) integration for [sabre/dav](https://sabre.io/dav/)

## What is this?

This project extends the [SabreDAV](https://sabre.io/dav/) framework with
authentication and principal backends for [FreeIPA](https://www.freeipa.org/).
You can use this to run your own CalDAV/CardDAV server that retrieves users and
groups from the local FreeIPA domain.

Two backends are provided:

- `\FreeIPA\AuthBackend`: this is an authentication backend that uses the
  `REMOTE_USER` environment variable set by the webserver. You should configure
  [mod\_gssapi](https://github.com/gssapi/mod_auth_gssapi) to handle user authentication.
  Optionally, you can limit logins to members of certain FreeIPA groups using the
  `$allowedGroups` parameter.

  Upon successful login, a default calendar and addressbook will be created for the
  user if none already exist.

- `\FreeIPA\PrincipalBackend`: this is a principal backend that retrieves users and
  groups from FreeIPA. You can (and should) limit the users and groups returned
  using the `$allowedGroups` parameter.

Both backends require `php-ldap` compiled with SASL support. Check `phpinfo()` to
verify you have a compatible version. In addition, the PHP process needs access
to kerberos credentials in order to perform LDAP queries (see [below](#apache-configuration)).

This project has been used successfully in the following environments:

  - Rocky Linux 8 with Apache 2.4 and PHP 7.4
  - Rocky Linux 9 with Apache 2.4 and PHP 8.0


## Limitations

SabreDAV assumes that user and group principals are both stored in the same
`principals/` namespace. Practically, this means that you can't have a user
and group in FreeIPA with the same name.

While you can [allegedly](https://sabre.io/dav/principals/#custom-principal-url-schemes)
work around this limitation, it is neither tested nor supported.

In the event a username and groupname clash, the user takes precendence and the
group will not be visible to SabreDAV.


## Setup

Clone this repostory into your webroot:

```bash
webroot=/var/www/html/sabredav
mkdir $webroot
git clone https://git.sacredheartsc.com/sabredav-freeipa $webroot
```

Install dependences using [composer](https://getcomposer.org/):

```bash
cd $webroot
composer install
```

Rename the sample configuration and modify to suit your needs:

```bash
cp server.example.php server.php
```

Most of this file is boilerplate common to all SabreDAV installations. Note the
salient FreeIPA parts:

```php
$ipa = new \FreeIPA\Connection();

$allowedGroups = [
  'dav-access'
];

$authBackend = new \FreeIPA\AuthBackend(
  $ipa,
  $caldavBackend,
  $carddavBackend,
  $allowedGroups);

$principalBackend = new \FreeIPA\PrincipalBackend(
  $ipa,
  $allowedGroups);
```

Note especially the `$allowedGroups` array. You should use this parameter to limit
the FreeIPA users and groups visible to SabreDAV. If you leave it empty, then all
users and groups will be visible. This is bad for two reasons:

1. It results in poor client experience by littering the interface with a
   bunch of groups that no one will ever use.

2. Sabredav makes a *lot* of group membership queries, seemingly on every
   request. Querying group memberships across your entire FreeIPA domain on
   every CalDAV operation is ridiculously expensive.

Consider the example configuration above. Assuming the `dav-access` FreeIPA group
looks like this:

    $ ipa group-show dav-access
    Group name: dav-access
    Description: CalDAV/CardDAV access
    Member groups: accounting, human-resources
    Indirect Member users: benedict, leo, michael

then SabreDAV would only see the following groups:
`dav-access`, `accounting`, `human-resources`

And similarly, only the members of those groups would show up as SabreDAV users:
`benedict`, `leo`, `michael`

This type of configuration is possible because FreeIPA supports nested groups
(a group itself can be a member of another group).


## Apache Configuration

The following apache configuration provides Kerberos SSO for SabreDAV, falling
back to Basic authentication. In addition, it redirects well-known URLs to aid
in client autodiscovery.

```apache
Redirect /.well-known/caldav  /server.php
Redirect /.well-known/carddav /server.php

RewriteEngine On
RewriteCond %{REQUEST_URI} !^/\.well-known/
RewriteRule .* /server.php [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]

<Location />
  AuthType GSSAPI
  AuthName "FreeIPA Single Sign-On"
  GssapiBasicAuth On
  GssapiNegotiateOnce On
  Require valid-user
</Location>
```

Apache needs a keytab for `HTTP/dav.example.com`, and PHP needs a kerberos ticket
to perform LDAP queries. The following `gssproxy.conf` snippet is sufficient (this
also works for kerberized postgres queries):

```dosini
[service/sabredav]
mechs = krb5
cred_store = client_keytab:/var/lib/gssproxy/clients/sabredav.keytab
euid = apache

[service/HTTP]
mechs = krb5
cred_store = keytab:/var/lib/gssproxy/clients/httpd.keytab
euid = apache
program = /usr/sbin/httpd
```

Be sure to export `GSS_AUTH_PROXY=yes` for your httpd and php-fpm daemons:

```
# /etc/systemd/system/httpd.service.d/override.conf
[Service]
Environment=GSS_USE_PROXY=yes

# /etc/php-fpm.d/www.conf
env[GSS_USE_PROXY] = yes
```

If you're not using gssproxy, you'll need the usual `KRB5_KTNAME` and
`KRB5_CLIENT_KTNAME` with appropriate permissions.

You'll also need the following if SELinux is enabled:

```bash
setsebool -P httpd_can_connect_ldap on
```
