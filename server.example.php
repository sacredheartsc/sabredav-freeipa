<?php
/**               -JMJ-
 *
 * Example sabredav configuration for FreeIPA
 *
 * @author stonewall
 * @license https://opensource.org/licenses/MIT
 * @version 0.01
 *
 * Rename this file to config.php and edit to suit your needs. After running
 * `composer install` in this directory, you should be good to go.
 */

// timezone
date_default_timezone_set('UTC');

// database
$pdo = new PDO('pgsql:dbname=sabredav;host=postgres.example.com', 'sabredav');
$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);

// autoloader
require_once 'vendor/autoload.php';

// freeipa
$ipa = new \FreeIPA\Connection();

/**
 * If $allowedGroups is nonempty, only users and groups that are members of one
 * of the specified groups will be visible to SabreDAV. Recall that in FreeIPA,
 * groups can be members of other groups.
 *
 * In addition, only members of one of the specified groups will be allowed to
 * login.
 *
 * If $allowedGroups is empty, then *every* FreeIPA user and *every* FreeIPA
 * group will be visible as a SabreDAV principal. This can cause performance
 * issues due to the large number of LDAP queries issued.
 */
$allowedGroups = [
  'dav-access'
];

// backends
$caldavBackend    = new \Sabre\CalDAV\Backend\PDO($pdo);
$carddavBackend   = new \Sabre\CardDAV\Backend\PDO($pdo);
$principalBackend = new \FreeIPA\PrincipalBackend($ipa, $allowedGroups);
$authBackend      = new \FreeIPA\AuthBackend($ipa, $caldavBackend, $carddavBackend, $allowedGroups);
$lockBackend      = new \Sabre\DAV\Locks\Backend\PDO($pdo);

// directory structure
$server = new Sabre\DAV\Server([
  new \Sabre\CalDAV\Principal\Collection($principalBackend),
  new \Sabre\CalDAV\CalendarRoot($principalBackend, $caldavBackend),
  new \Sabre\CardDAV\AddressBookRoot($principalBackend, $carddavBackend),
  new \Sabre\DAVACL\FS\HomeCollection($principalBackend, __DIR__."/webdav")
]);

// if you run sabredav from a subdirectory, set it here
$server->setBaseUri('/');

// plugins
$server->addPlugin(new \Sabre\DAV\Auth\Plugin($authBackend,'SabreDAV'));
$server->addPlugin(new \Sabre\DAV\Browser\Plugin());
$server->addPlugin(new \Sabre\DAV\Sync\Plugin());
$server->addPlugin(new \Sabre\DAV\Sharing\Plugin());
$server->addPlugin(new \Sabre\DAV\Locks\Plugin($lockBackend));
$server->addPlugin(new \Sabre\DAV\Browser\GuessContentType());
$server->addPlugin(new \Sabre\DAV\TemporaryFileFilterPlugin(__DIR__."/tmpdata"));

$aclPlugin = new \Sabre\DAVACL\Plugin();
$aclPlugin->hideNodesFromListings = true;
$server->addPlugin($aclPlugin);

// caldav plugins
$server->addPlugin(new \Sabre\CalDAV\Plugin());
$server->addPlugin(new \Sabre\CalDAV\Schedule\Plugin());
$server->addPlugin(new \Sabre\CalDAV\Schedule\IMipPlugin('calendar-noreply@example.com'));
$server->addPlugin(new \Sabre\CalDAV\Subscriptions\Plugin());
$server->addPlugin(new \Sabre\CalDAV\Notifications\Plugin());
$server->addPlugin(new \Sabre\CalDAV\SharingPlugin());
$server->addPlugin(new \Sabre\CalDAV\ICSExportPlugin());

// carddav plugins
$server->addPlugin(new \Sabre\CardDAV\Plugin());
$server->addPlugin(new \Sabre\CardDAV\VCFExportPlugin());

// run the server
$server->exec();
