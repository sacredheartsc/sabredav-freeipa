<?php
/**               -JMJ-
 *
 * FreeIPA group definition
 *
 * @author stonewall
 * @license https://opensource.org/licenses/MIT
 * @version 0.01
 *
 * This class represents a FreeIPA group object. It cannot not be instantiated
 * directly. Rather, use the static Group::get() or Group::search() methods
 * to retrieve one or more groups.
 */

declare(strict_types=1);

namespace FreeIPA;

class Group {
  const PRINCIPAL_PREFIX  = 'principals/';
  const LDAP_CONTAINER    = 'cn=groups,cn=accounts';
  const LDAP_OBJECT_CLASS = 'groupofnames';
  const LDAP_ATTRIBUTES   = ['cn', 'description'];

  const LDAP_FIELD_MAP = [
    '{DAV:}displayname' => 'description',
    '{http://sabredav.org/ns}email-address' => 'mail'
  ];

  protected $name;
  protected $description;

  protected function __construct($name, $description) {
    $this->name = $name;
    $this->description = $description;
  }

  /**
   * Construct a Group object from an LDAP group entry.
   *
   * @param array $entry
   *
   * @return \FreeIPA\Group
   */
  protected static function fromLdapEntry($entry) {
    return new self(
      $entry['cn'][0],
      isset($entry['description'][0]) ? $entry['description'][0] : $entry['cn'][0]
    );
  }

  /**
   * Returns an array of Group objects for each group in the FreeIPA directory matching
   * the given DAV search properties, subject to $allowedGroups.
   *
   * @param \FreeIPA\Connection $ipaConn          : freeipa connection object
   * @param array               $searchProperties : search conditions, as requested by SabreDAV
   * @param string              $test             : either 'allof' or 'anyof'
   * @param array               $allowedGroups    : only consider the given groups
   *
   * @return array
   */
  public static function search(
    \FreeIPA\Connection $ipaConn,
    array $searchProperties = [],
    $test = 'anyof',
    array $allowedGroups = [])
  {
    $groups = [];

    // for each group matching $filter
    if ($entries = $ipaConn->search(
      self::LDAP_CONTAINER,
      Util::buildFilter('allof',
        ['objectClass', self::LDAP_OBJECT_CLASS],
        Util::buildMemberOfFilter($ipaConn, $allowedGroups, true),
        Util::buildPrincipalFilter($searchProperties, self::LDAP_FIELD_MAP, $test)),
      self::LDAP_ATTRIBUTES))
    {
      for ($i = 0; $i < $entries['count']; $i++) {
        $groups[] = self::fromLdapEntry($entries[$i]);
      }
    }
    return $groups;
  }

  /**
   * Returns the Group from FreeIPA with the given groupname that matches the
   * given DAV search properties, subject to $allowedGroups.
   *
   * If no matching group is found, null is returned.
   *
   * @param \FreeIPA\Connection $ipaConn          : freeipa connection object
   * @param string              $groupname        : freeipa group cn
   * @param array               $searchProperties : search conditions, as requested by SabreDAV
   * @param string              $test             : either 'allof' or 'anyof'
   * @param array               $allowedGroups    : only consider the given groups
   *
   * @return \FreeIPA\Group|null
   */
  public static function get(
    \FreeIPA\Connection $ipaConn,
    $groupname,
    array $searchProperties = [],
    $test = 'anyof',
    array $allowedGroups = [])
  {
    if ($entry = $ipaConn->read(
      self::getRelativeDn($groupname),
      Util::buildFilter('allof',
        ['objectClass', self::LDAP_OBJECT_CLASS],
        Util::buildMemberOfFilter($ipaConn, $allowedGroups, true),
        Util::buildPrincipalFilter($searchProperties, self::LDAP_FIELD_MAP, $test)),
      self::LDAP_ATTRIBUTES))
    {
      return self::fromLdapEntry($entry);
    }
    return null;
  }

  /**
   * Convert a groupname to an escaped relative LDAP DN
   *
   * For example:
   *   getRelativeDn('hr') -> 'uid=\68\72,cn=groups,cn=accounts'
   *
   * @param string $groupname
   *
   * @return string
   */
  public static function getRelativeDn($groupname) {
    return 'cn=' . ldap_escape($groupname) . ',' . self::LDAP_CONTAINER;
  }

  /**
   * Returns an array of principal URIs corresponding to each of the group's
   * members, subject to $allowedGroups.
   *
   * @param \FreeIPA\Connection $ipaConn       : freeipa connection object
   * @param array               $allowedGroups : only consider members of the given groups
   *
   * @return array
   */
  public function getMemberPrincipals(\FreeIPA\Connection $ipaConn, array $allowedGroups = []) {
    $memberPrincipals = [];

    if ($entries = $ipaConn->search(
      User::LDAP_CONTAINER,
      Util::buildFilter('allof',
        ['objectClass', User::LDAP_OBJECT_CLASS],
        ['memberof',  $ipaConn->resolveDn(self::getRelativeDn($this->name))],
        Util::buildMemberOfFilter($ipaConn, $allowedGroups)),
      ['uid']))
    {
      for ($i = 0; $i < $entries['count']; $i++) {
        $memberPrincipals[] = User::PRINCIPAL_PREFIX . $entries[$i]['uid'][0];
      }
    }
    return $memberPrincipals;
  }

  /**
   * Convert a Group to SabreDAV's representation of a principal.
   *
   * @return array
   */
  public function toPrincipal() {
    return [
      'uri' => self::PRINCIPAL_PREFIX . $this->name,
      '{DAV:}displayname' => $this->description
    ];
  }

  /**
   * Get the groupname.
   *
   * @return string
   */
  public function getName() {
    return $this->name;
  }
}
