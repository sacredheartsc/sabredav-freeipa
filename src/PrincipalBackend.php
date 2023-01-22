<?php
/**               -JMJ-
 *
 * FreeIPA/LDAP principal backend
 *
 * @author stonewall@sacredheartsc.com
 * @license https://opensource.org/licenses/MIT
 * @version 0.01
 *
 * This backend constructs principals from the users and groups in the local
 * FreeIPA domain.
 *
 * php-ldap compiled with SASL support is required, along with accessible
 * kerberos credentials. Check the README for more information.
 *
 * Note that since sabredav assumes that users and groups exist in the same
 * namespace, you can't have a FreeIPA user and FreeIPA group with the same
 * name. In the event of a clash, only the user object is visible to sabredav.
 *
 * Add this backend in server.php with the following invocation:
 *
 *   $ipa = new \FreeIPA\Connection();
 *   $allowedGroups = ['sabredav-access'];
 *   $principalBackend = new \FreeIPA\PrincipalBackend($ipa, $allowedGroups);
 *
 * If the $allowedGroups argument is given, then only members of one of the
 * specified groups are visible to sabredav.
 *
 * NOTE: This applies to both users AND groups!! (FreeIPA supports nested groups.)
 *
 * For example, if set $allowGroups = ['dav-access'], and the corresponding
 * FreeIPA group looks like this:
 *
 *   $ ipa group-show dav-access
 *   Group name: dav-access
 *   Description: CalDAV/CardDAV access
 *   Member groups: accounting, human-resources
 *   Indirect Member users: benedict, leo, michael
 *
 * Then sabredav would only see the following groups:
 *   - dav-access
 *   - accounting
 *   - human-resources
 *
 * and similarly, only the following users:
 *   - benedict
 *   - leo
 *   - michael
 *
 * If you don't set $allowedGroups, then all users and groups in your FreeIPA
 * domain will be visible to sabredav. I don't recommend doing this, for two
 * reasons:
 *
 * 1. It results in poor client experience by littering the interface with a
 *    bunch of groups that no one will ever use.
 *
 * 2. Sabredav makes a *lot* of group membership queries, seemingly on every
 *    request. Querying group memberships across your entire FreeIPA domain on
 *    every CalDAV operation is ridiculously expensive.
 */

declare(strict_types=1);

namespace FreeIPA;

class PrincipalBackend extends \Sabre\DAVACL\PrincipalBackend\AbstractBackend {

  const PRINCIPAL_PREFIX = 'principals/';

  const PROXY_CHILDREN = [
    'calendar-proxy-read',
    'calendar-proxy-write'
  ];

  protected $ipa;
  protected $allowedGroups;

  public function __construct(\FreeIPA\Connection $ipa, $allowedGroups = []) {
    $this->ipa = $ipa;
    $this->allowedGroups = $allowedGroups;
  }

  /**
   * Splits a string on the path separator (/). If any resulting substrings are
   * empty, they are discarded.
   *
   * For example:
   *   splitPath('/one//two/') -> ['one', 'two']
   *
   * @param string $path
   * @return array
   */
  protected static function splitPath($path) {
    return preg_split('/\//', $path, -1, PREG_SPLIT_NO_EMPTY);
  }

  /**
   * Returns an array of principals for each user and group in the FreeIPA domain,
   * subject to $allowedGroups.
   *
   * If $searchProperties is specified, only users or groups matching the given
   * criteria are returned.
   *
   * If a matching user and group both have the same name, the group is ignored.
   *
   * @param array  $searchProperties : DAV search properties
   * @param string $test             : either 'anyof' or 'allof'
   *
   * @return array : array of associative arrays, each representing a principal
   */
  protected function getPrincipals(array $searchProperties = [], $test = 'anyof') {
    $principals = [];

    // Get groups.
    foreach(Group::search($this->ipa, $searchProperties, $test, $this->allowedGroups) as $group) {
      $principals[$group->getName()] = $group->toPrincipal();
    }

    // Get users. If a user and a group have the name name, the user wins.
    foreach(User::search($this->ipa, $searchProperties, $test, $this->allowedGroups) as $user) {
      $principals[$user->getUid()] = $user->toPrincipal();
    }

    return array_values($principals);
  }

  /**
   * Returns a principal for the user or group with the given name, subject to
   * $allowedGroups.
   *
   * If $searchProperties is specified, only a user or group matching the given
   * criteria is returned.
   *
   * If a matching user and group both have the same name, the user principal is
   * returned.
   *
   * If no matching user or group is found, null is returned.
   *
   * @param string $name             : user or group name
   * @param array  $searchProperties : DAV search properties
   * @param string $test             : either 'anyof' or 'allof'
   *
   * @return array|null : associative array representing the principal
   */
  protected function getPrincipal($name, array $searchProperties = [], $test = 'anyof') {
    if ($user = User::get($this->ipa, $name, $searchProperties, $test, $this->allowedGroups)) {
      return $user->toPrincipal();
    } elseif ($group = Group::get($this->ipa, $name, $searchProperties, $test, $this->allowedGroups)) {
      return $group->toPrincipal();
    }
    return null;
  }

  /**
   * Returns an array of principals corresponding to each DAV proxy principal for
   * the given user or group, subject to $allowedGroups.
   *
   * If $searchProperties is specified, only proxy principals for a user or group
   * matching the given criteria are considered.
   *
   * If a matching user and group both have the same name, the user is used.
   *
   * @param string $name             : user or group name
   * @param array  $searchProperties : DAV search properties
   * @param string $test             : either 'anyof' or 'allof'
   *
   * @return array : array of associative arrays, each representing a proxy principal
   */
  protected function getPrincipalChildren($name, array $searchProperties = [], $test = 'anyof') {
    $principals = [];

    if ($parent = $this->getPrincipal($name, $searchProperties, $test)) {
      foreach (self::PROXY_CHILDREN as $child) {
        $principals[] = [ 'uri' => "$parent[uri]/$child" ];
      }
    }
    return $principals;
  }

  /**
   * Returns a principals corresponding to the requested proxy principal for
   * the given user or group, subject to $allowedGroups.
   *
   * If $searchProperties is specified, only a user or group matching the given
   * criteria is considered.
   *
   * If no matching user or group is found, null is returned.
   *
   * @param string $name             : user or group name
   * @param string $childName        : proxy principal name
   * @param array  $searchProperties : DAV search properties
   * @param string $test             : either 'anyof' or 'allof'
   *
   * @return array|null : associative array representing the proxy principal
   */
  protected function getPrincipalChild($name, $childName, array $searchProperties = [], $test = 'anyof') {
    if (in_array($childName, self::PROXY_CHILDREN)) {
      if ($parent = $this->getPrincipal($name, $searchProperties, $test)) {
        return [ 'uri' => "$parent[uri]/$childName" ];
      }
    }
    return null;
  }

  /**
   * Returns a list of principals based on a prefix.
   *
   * This prefix will often contain something like 'principals'. You are only
   * expected to return principals that are in this base path.
   *
   * You are expected to return at least a 'uri' for every user, you can
   * return any additional properties if you wish so. Common properties are:
   *   {DAV:}displayname
   *   {http://sabredav.org/ns}email-address - This is a custom SabreDAV
   *     field that's actually injected in a number of other properties. If
   *     you have an email address, use this property.
   *
   * @param string $prefixPath
   *
   * @return array
   */
  public function getPrincipalsByPrefix($prefixPath) {
    $parts = self::splitPath($prefixPath);

    if ($parts[0] == 'principals') {
      switch (count($parts)) {
        case 1: return $this->getPrincipals();
        case 2: return $this->getPrincipalChildren($parts[1]);
      }
    }
    return [];
  }

  /**
   * Returns a specific principal, specified by it's path.
   * The returned structure should be the exact same as from
   * getPrincipalsByPrefix.
   *
   * @param string $path
   *
   * @return array
   */
  public function getPrincipalByPath($path) {
    $parts = self::splitPath($path);

    if ($parts[0] == 'principals') {
      switch(count($parts)) {
        case 2: return $this->getPrincipal($parts[1]);
        case 3: return $this->getPrincipalChild($parts[1], $parts[2]);
      }
    }
    return null;
  }

  /**
   * Updates one ore more webdav properties on a principal.
   *
   * The list of mutations is stored in a Sabre\DAV\PropPatch object.
   * To do the actual updates, you must tell this object which properties
   * you're going to process with the handle() method.
   *
   * Calling the handle method is like telling the PropPatch object "I
   * promise I can handle updating this property".
   *
   * Read the PropPatch documentation for more info and examples.
   *
   * @param string $path
   */
  public function updatePrincipal($path, \Sabre\DAV\PropPatch $propPatch) {
    throw new \Sabre\DAV\Exception\Forbidden('Permission denied to modify LDAP-backed principal');
  }

  /**
   * This method is used to search for principals matching a set of
   * properties.
   *
   * This search is specifically used by RFC3744's principal-property-search
   * REPORT.
   *
   * The actual search should be a unicode-non-case-sensitive search. The
   * keys in searchProperties are the WebDAV property names, while the values
   * are the property values to search on.
   *
   * By default, if multiple properties are submitted to this method, the
   * various properties should be combined with 'AND'. If $test is set to
   * 'anyof', it should be combined using 'OR'.
   *
   * This method should simply return an array with full principal uri's.
   *
   * If somebody attempted to search on a property the backend does not
   * support, you should simply return 0 results.
   *
   * You can also just return 0 results if you choose to not support
   * searching at all, but keep in mind that this may stop certain features
   * from working.
   *
   * @param string $prefixPath
   * @param string $test
   *
   * @return array
   */
  public function searchPrincipals($prefixPath, array $searchProperties, $test = 'allof') {
    $principals = [];
    $parts = self::splitPath($prefixPath);

    if ($parts[0] == 'principals') {
      switch (count($parts)) {
        case 1: $principals = $this->getPrincipals($searchProperties, $test);
        case 2: $principals = $this->getPrincipalChildren($parts[1], $searchProperties, $test);
      }
    }
    return array_map(function($p) { return $p['uri']; }, $principals);
  }

  /**
   * Finds a principal by its URI.
   *
   * This method may receive any type of uri, but mailto: addresses will be
   * the most common.
   *
   * Implementation of this API is optional. It is currently used by the
   * CalDAV system to find principals based on their email addresses. If this
   * API is not implemented, some features may not work correctly.
   *
   * This method must return a relative principal path, or null, if the
   * principal was not found or you refuse to find it.
   *
   * @param string $uri
   * @param string $principalPrefix
   *
   * @return string|null
   */
  public function findByUri($uri, $principalPrefix) {
    $uriParts = \Sabre\Uri\parse($uri);
    $prefixParts = self::splitPath($principalPrefix);

    if (empty($uriParts['path'])) {
      return null;
    }

    if ('mailto' === $uriParts['scheme']) {
      if ($prefixParts === ['principals']) {
        $results = $this->getPrincipals(['{http://sabredav.org/ns}email-address' => $uriParts['path']]);
        if (count($results) > 0) {
          return $results[0]['uri'];
        }
      }
    } else {
      if (array_slice(self::splitPath($uriParts['path']), 0 -1) === array_slice($prefixParts, 0, -1)) {
        return $this->getPrincipalByPath($uriParts['path']) ? $uriParts['path'] : null;
      }
    }
    return null;
  }

  /**
   * Returns the list of members for a group-principal.
   *
   * @param string $principal
   *
   * @return array
   */
  public function getGroupMemberSet($principal) {
    $parts = self::splitPath($principal);

    if (count($parts) == 2 && $parts[0] == 'principals') {
      if ($group = Group::get($this->ipa, $parts[1])) {
        return $group->getMemberPrincipals($this->ipa);
      } elseif ($user = User::get($this->ipa, $parts[1])) {
        return []; // if principal is a user, just return nothing
      } else {
        throw new \Sabre\DAV\Exception('Principal not found');
      }
    }
    return [];
  }

  /**
   * Returns the list of groups a principal is a member of.
   *
   * @param string $principal
   *
   * @return array
   */
  public function getGroupMembership($principal) {
    $parts = self::splitPath($principal);

    if (count($parts) == 2 && $parts[0] == 'principals') {
      if ($user = User::get($this->ipa, $parts[1])) {
        return $user->getGroupPrincipals($this->ipa, $this->allowedGroups);
      } elseif ($group = Group::get($this->ipa, $parts[1])) {
        return []; // if principal is a group, just return nothing
      } else {
        throw new \Sabre\DAV\Exception('Principal not found');
      }
    }
    return [];
  }

  /**
   * Updates the list of group members for a group principal.
   *
   * The principals should be passed as a list of uri's.
   *
   * @param string $principal
   */
  public function setGroupMemberSet($principal, array $members) {
    throw new \Sabre\DAV\Exception\Forbidden('Permission denied to modify LDAP-backed principal');
  }

  /**
   * Sets the groups from which user and group principals will be considered.
   *
   * @param array $allowedGroups
   */
  public function setAllowedGroups(array $allowedGroups) {
    $this->allowedGroups = $allowedGroups;
  }
}
