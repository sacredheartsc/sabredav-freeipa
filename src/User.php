<?php
/**               -JMJ-
 *
 * FreeIPA user definition
 *
 * @author stonewall
 * @license https://opensource.org/licenses/MIT
 * @version 0.01
 *
 * This class represents a FreeIPA user object. It cannot not be instantiated
 * directly. Rather, use the static User::get() or User::search() methods
 * to retrieve one or more users.
 */

declare(strict_types=1);

namespace FreeIPA;

class User {
  const PRINCIPAL_PREFIX  = 'principals/';
  const LDAP_CONTAINER    = 'cn=users,cn=accounts';
  const LDAP_OBJECT_CLASS = 'person';
  const LDAP_ATTRIBUTES   = ['uid', 'displayname', 'mail'];

  const LDAP_FIELD_MAP = [
    '{DAV:}displayname' => 'displayname',
    '{http://sabredav.org/ns}email-address' => 'mail'
  ];

  protected $uid;
  protected $displayName;
  protected $email;

  protected function __construct($uid, $displayName, $email) {
    $this->uid = $uid;
    $this->displayName = $displayName;
    $this->email = $email;
  }

  /**
   * Construct a User object from an LDAP user entry.
   *
   * @param array $entry
   *
   * @return \FreeIPA\User
   */
  protected static function fromLdapEntry(array $entry) {
    return new self(
      $entry['uid'][0],
      isset($entry['displayname'][0]) ? $entry['displayname'][0] : $entry['uid'][0],
      $entry['mail'][0]
    );
  }

  /**
   * Convert a username to an escaped relative LDAP DN
   *
   * For example:
   *   getRelativeDn('joe') -> 'uid=\6a\6f\65,cn=users,cn=accounts'
   *
   * @param string $username
   *
   * @return string
   */
  public static function getRelativeDn($username) {
    return 'uid=' . ldap_escape($username) . ',' . self::LDAP_CONTAINER;
  }


  /**
   * Returns an array of User objects for each user in the FreeIPA directory matching
   * the given DAV search properties, subject to $allowedGroups.
   *
   * @param \FreeIPA\Connection $ipaConn          : freeipa connection object
   * @param array               $searchProperties : search conditions, as requested by SabreDAV
   * @param string              $test             : either 'allof' or 'anyof'
   * @param array               $allowedGroups    : only consider members of the given groups
   *
   * @return array
   */
  public static function search(
    \FreeIPA\Connection $ipaConn,
    array $searchProperties = [],
    $test = 'allof',
    array $allowedGroups = [])
  {
    $users = [];

    // for each user matching filter
    if ($entries = $ipaConn->search(
      self::LDAP_CONTAINER,
      Util::buildFilter('allof',
        ['objectClass', self::LDAP_OBJECT_CLASS],
        'mail=*',
        Util::buildMemberOfFilter($ipaConn, $allowedGroups),
        Util::buildPrincipalFilter($searchProperties, self::LDAP_FIELD_MAP, $test)),
      self::LDAP_ATTRIBUTES))
    {
      for ($i = 0; $i < $entries['count']; $i++) {
        $users[] = self::fromLdapEntry($entries[$i]);
      }
    }
    return $users;
  }

  /**
   * Returns the User from FreeIPA with the given username that matches the
   * given DAV search properties, subject to $allowedGroups.
   *
   * If no matching user is found, null is returned.
   *
   * @param \FreeIPA\Connection $ipaConn          : freeipa connection object
   * @param string              $username         : freeipa user uid
   * @param array               $searchProperties : search conditions, as requested by SabreDAV
   * @param string              $test             : either 'allof' or 'anyof'
   * @param array               $allowedGroups    : only consider members of the given groups
   *
   * @return \FreeIPA\User|null
   */
  public static function get(
    \FreeIPA\Connection $ipaConn,
    $username,
    array $searchProperties = [],
    $test = 'allof',
    array $allowedGroups = [])
  {
    if ($entry = $ipaConn->read(
      self::getRelativeDn($username),
      Util::buildFilter('allof',
        ['objectClass', self::LDAP_OBJECT_CLASS],
        'mail=*',
        Util::buildMemberOfFilter($ipaConn, $allowedGroups),
        Util::buildPrincipalFilter($searchProperties, self::LDAP_FIELD_MAP, $test)),
      self::LDAP_ATTRIBUTES))
    {
      return self::fromLdapEntry($entry);
    }
    return null;
  }

  /**
   * Returns an array of principal URIs corresponding to each of the user's
   * groups, subject to $allowedGroups.
   *
   * @param \FreeIPA\Connection $ipaConn       : freeipa connection object
   * @param array               $allowedGroups : only consider the given groups
   *
   * @return array
   */
  public function getGroupPrincipals($ipaConn, $allowedGroups = []) {
    $groupPrincipals = [];

    // get the user's groups
    if ($userEntry = $ipaConn->read(
      self::getRelativeDn($this->uid),
      Util::buildFilter('allof',
        ['objectClass', self::LDAP_OBJECT_CLASS],
        'mail=*',
        Util::buildMemberOfFilter($ipaConn, $allowedGroups)),
      ['uid', 'memberof']))
    {
      // get all allowed groups (and resolve any nested groups)
      if ($allowedGroupEntries = $ipaConn->search(
        Group::LDAP_CONTAINER,
        Util::buildFilter('allof',
          ['objectClass', Group::LDAP_OBJECT_CLASS],
          Util::buildMemberOfFilter($ipaConn, $allowedGroups, true)),
        ['cn']))
      {
        // get the intersection of user's groups and allowed groups
        for ($i = 0; $i < $userEntry['memberof']['count']; $i++) {
          for ($j = 0; $j < $allowedGroupEntries['count']; $j++) {
            if ($userEntry['memberof'][$i] == $allowedGroupEntries[$j]['dn']) {
              $groupPrincipals[] = Group::PRINCIPAL_PREFIX . $allowedGroupEntries[$j]['cn'][0];
            }
          }
        }
      }
    }
    return $groupPrincipals;
  }

  /**
   * Convert a User to SabreDAV's representation of a principal.
   *
   * @return array
   */
  public function toPrincipal() {
    return [
      'uri' => self::PRINCIPAL_PREFIX . $this->uid,
      '{DAV:}displayname' => $this->displayName,
      '{http://sabredav.org/ns}email-address' => $this->email
    ];
  }

  /**
   * Get the username.
   *
   * @return string
   */
  public function getUid() {
    return $this->uid;
  }
}
