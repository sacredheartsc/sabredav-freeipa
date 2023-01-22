<?php
/**               -JMJ-
 *
 * FreeIPA utility class
 *
 * @author stonewall@sacredheartsc.com
 * @license https://opensource.org/licenses/MIT
 * @version 0.01
 *
 * This class contains various helper functions for querying FreeIPA.
 * Static methods only.
 */

declare(strict_types=1);

namespace FreeIPA;

class Util {

  private function __construct() { }

  /**
   * Given a list of conditions, construct an ldap filter. The conditions can
   * be raw strings (eg. "attr=value") or an array of attribute-value pairs.
   *
   * If a string is given, the enclosing parens are optional.
   *
   * If no conditions are provided, then the empty string is returned.
   *
   * For example:
   *   buildFilter('allof', 'mail=*', ['givenname', 'padre', 'sn', 'pio'])
   *     -> '(&(mail=*)(givenname=padre)(sn=pio))'
   *
   * @param string $test       : either 'allof' (&) or 'anyof' (|)
   * @param mixed string|array : filter conditions
   *
   * @return string
   */
  public static function buildFilter($test, ...$conditions) {
    $filter = '';

    foreach ($conditions as $condition) {
      if (is_array($condition)) {
        for ($i = 0; $i < count($condition); $i+=2) {
          $filter .= "({$condition[$i]}={$condition[$i+1]})";
        }
      } elseif (!empty($condition)) {
        if ($condition[0] != '(' && $condition[-1] != ')') {
          $condition = "($condition)";
        }
        $filter .= $condition;
      }
    }

    if ($filter) {
      $filter = '(' . ($test === 'anyof' ? '|' : '&') . $filter . ')';
    }
    return $filter;
  }

  /**
   * Given a list of DAV search properties and a mapping of DAV property names
   * to LDAP attribute names, construct an LDAP filter.
   *
   * If no conditions are provided, then the empty string is returned.
   *
   * If a search property is given that does not exist in the LDAP mapping, then
   * a BadRequest exception is thrown.
   *
   * @param array  $searchProperties : search conditions, as requested by SabreDAV
   * @param array  $fieldMap         : mapping of DAV properties to LDAP attributes
   * @param string $test             : either 'allof' of 'anyof'
   *
   * @return string
   */
  public static function buildPrincipalFilter($searchProperties = [], $fieldMap = [], $test = 'allof') {
    $conditions = [];

    foreach ($searchProperties as $property => $value) {
      if (isset($fieldMap[$property])) {
        $conditions[] = [$fieldMap[$property].':caseIgnoreIA5Match:', '*'.ldap_escape($value).'*'];
      } else {
        throw new \Sabre\DAV\Exception\BadRequest("Unknown property: $property");
      }
    }
    return self::buildFilter($test, ...$conditions);
  }

  /**
   * Given a list of group names, construct an ldap filter to test for membership
   * in at least one of the groups.
   *
   * If $includeSelf == true, then each group object will be matched along with
   * its members. The option is useful for getting all the groups in a nested
   * hierarchy.
   *
   * @param \FreeIPA\Connection $ipaConn     : freeipa connection object
   * @param array               $groupnames  : list of group names
   * @param bool                $includeSelf : whether to match the groups themselves
   *
   * @return string
   */
  public static function buildMemberOfFilter(\FreeIPA\Connection $ipaConn, $groupnames, $includeSelf = false) {
    $conditions = [];

    foreach ($groupnames as $groupname) {
      $conditions[] = ['memberOf', $ipaConn->resolveDn(Group::getRelativeDn($groupname))];
      if ($includeSelf) {
        $conditions[] = 'cn=' . ldap_escape($groupname);
      }
    }
    return self::buildFilter('anyof', ...$conditions);
  }
}
