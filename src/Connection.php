<?php
/**               -JMJ-
 *
 * FreeIPA connection definition
 *
 * @author stonewall
 * @license https://opensource.org/licenses/MIT
 * @version 0.01
 *
 * This class represents a connection to a FreeIPA domain. An instance should
 * be instantiated in server.php and passed to the FreeIPA\AuthBackend and
 * FreeIPA\PrincipalBackend objects.
 *
 * No arguments are necessary, but you may override the autodetection with
 * the following invocation:
 *
 *   new \FreeIPA\Connection((
 *     domain  = null,
 *     realm   = null,
 *     baseDn  = null,
 *     ldapUri = null
 *   )
 */

declare(strict_types=1);

namespace FreeIPA;

use Sabre\DAV\Exception;

class Connection {

  protected $realm;
  protected $domain;
  protected $baseDn;
  protected $ldapUri;
  protected $ldapConn;

  /**
   * Discover the local DNS domain by querying the local FQDN.
   */
  protected function discoverDnsDomain() {
    if ($localFqdn = gethostbyaddr(gethostbyname(gethostname()))) {
      $domain = strtolower(explode('.', $localFqdn, 2)[1]);
      if (!in_array($domain, [$localFqdn, 'localhost', 'localdomain', 'localhost.localdomain'])) {
        return $this->domain = $domain;
      }
    }
    throw new Exception("Failed to discover local FreeIPA domain");
  }

  /**
   * Discover the local kerberos realm by querying the _kerberos SRV record.
   */
  protected function discoverKerberosRealm() {
    if ($kerberosTxtRecord = dns_get_record("_kerberos.{$this->domain}", DNS_TXT)) {
      return $this->realm = $kerberosTxtRecord[0]['txt'];
    }
    return $this->realm = strtoupper($this->domain);
  }

  /**
   * Discover the local LDAP servers by querying the _ldap SRV record.
   */
  protected function discoverLdapServers() {
    if ($ldapSrvRecords = dns_get_record("_ldap._tcp.{$this->domain}", DNS_SRV)) {
      return $this->ldapUri = implode(' ' , array_map(function($record) {
        return "ldap://$record[target]:$record[port]";
      }, $ldapSrvRecords));
    }
    throw new Exception("Failed to discover local LDAP servers via DNS");
  }

  /**
   * Discover the LDAP basedn by querying the root DSE. On failure, guess the basedn
   * from the local kerberos realm.
   */
  protected function discoverBaseDn() {
    $results = ldap_read($this->ldapConn, '', 'objectClass=*', ['defaultnamingcontext']);
    if ($results && ldap_count_entries($this->ldapConn, $results) == 1) {
      if ($rootDse = ldap_first_entry($this->ldapConn, $results)) {
        $attributes = ldap_get_attributes($this->ldapConn, $rootDse);
        if ($attributes['defaultnamingcontext']['count'] == 1) {
          return $this->baseDn = $attributes['defaultnamingcontext'][0];
        }
      }
    }
    return $this->guessBaseDnFromRealm();
  }

  /**
   * Construct an (assumed) LDAP basen from the components of the local kerberos realm.
   *
   * @return string
   */
  protected function guessBaseDnFromRealm() {
    $this->baseDn = implode(',', preg_filter('/^/', 'dc=', explode('.', strtolower($this->realm))));
  }

  public function __construct($domain = null, $realm = null, $baseDn = null, $ldapUri = null) {
    if (!function_exists('ldap_connect')) {
      throw new Exception('FreeIPA integration requires php-ldap, and it is not installed');
    }

    // get local domain
    if (!empty($domain)) {
      $this->domain = $domain;
    } else {
      $this->discoverDnsDomain();
    }

    // get local realm
    if (!empty($realm)) {
      $this->realm = $realm;
    } else {
      $this->discoverKerberosRealm();
    }

    // get ldap servers
    if (!empty($ldapUri)) {
      $this->ldapUri = $ldapUri;
    } else {
      $this->discoverLdapServers();
    }

    // connect to ldap server
    if (!($this->ldapConn = ldap_connect($this->ldapUri))) {
      throw new Exception("Failed to connect to FreeIPA LDAP server");
    }

    // set protocol version 3
    if (!ldap_set_option($this->ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3)) {
      throw new Exception("Failed to set LDAP protocol version");
    }

    // start TLS session
    if(!ldap_start_tls($this->ldapConn)) {
      throw new Exception("Failed to establish TLS session with LDAP server");
    }

    // bind to ldap server using kerberos credentials
    if (!ldap_sasl_bind($this->ldapConn, '', '', 'GSSAPI')) {
      throw new Exception("Failed to bind to LDAP server");
    }

    // get base dn
    if (!empty($baseDn)) {
      $this->basedn = $baseDn;
    } else {
      $this->discoverBaseDn();
    }
  }

  /**
   * Perform an LDAP search of the FreeIPA directory with subtree scope.
   *
   * @param string $container : ldap container relative to basedn (eg. 'cn=users,cn=accounts')
   * @param string $filter    : ldap filter
   * @param array $attributes : ldap attributes to return
   *
   * @return array|false
   */
  public function search($container = null, $filter = null, $attributes = []) {
    if ($result = ldap_search(
      $this->ldapConn,
      ($container ? "{$container},{$this->baseDn}" : $this->baseDn),
      ($filter ? $filter : '(objectClass=*)'),
      $attributes))
    {
      if ($entries = ldap_get_entries($this->ldapConn, $result)) {
        if ($entries['count'] > 0) {
          return $entries;
        }
      }
    }
    return false;
  }

  /**
   * Perform an LDAP search of the FreeIPA directory with subtree base.
   *
   * @param string $container : ldap container relative to basedn (eg. 'cn=users,cn=accounts')
   * @param string $filter    : ldap filter
   * @param array $attributes : ldap attributes to return
   *
   * @return array|false
   */
  public function read($container = null, $filter = null, $attributes = []) {
    if ($result = ldap_read(
      $this->ldapConn,
      ($container ? "{$container},{$this->baseDn}" : $this->baseDn),
      ($filter ? $filter : '(objectClass=*)'),
      $attributes))
    {
      if ($entries = ldap_get_entries($this->ldapConn, $result)) {
        if ($entries['count'] > 0) {
          return $entries[0];
        }
      }
    }
    return false;
  }

  /**
   * Given a list of DN components relative to the base DN, constructs the
   * fully-qualified DN.
   *
   * For example:
   *   resolveDn('uid=joseph', 'cn=users,cn=accounts')
   *     -> 'uid=joseph,cn=users,cn=accounts,dc=ipa,dc=example,dc=com'
   *
   * @param string $components...
   *
   * @return string
   */
  public function resolveDn(...$components) {
    return implode(',', array_merge($components, [$this->baseDn]));
  }

  /**
   * Returns the local kerberos realm.
   *
   * @return string
   */
  public function getRealm() {
    return $this->realm;
  }
}
