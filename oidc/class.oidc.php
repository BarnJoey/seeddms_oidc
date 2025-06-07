<?php

/***************************************************************
 *  Copyright notice
 *
 *  (c) 2025 BarnJoey<jm@salisburyit.us>
 *  (c) 2022 Eweol<eweol@outlook.com>
 *  (c) 2013 Uwe Steinmann <uwe@steinmann.cx>
 *  All rights reserved
 *
 *  This script is part of the SeedDMS project. The SeedDMS project is
 *  free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  The GNU General Public License can be found at
 *  http://www.gnu.org/copyleft/gpl.html.
 *
 *  This script is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  This copyright notice MUST APPEAR in all copies of the script!
 ***************************************************************/

/**
 * OIDC extension
 *
 * @author  Eweol <eweol@outlook.com>
 * @package SeedDMS
 * @subpackage  OIDC
 */
class SeedDMS_OIDC extends SeedDMS_ExtBase
{

	/**
	 * Initialization
	 *
	 * Use this method to do some initialization like setting up the hooks
	 * You have access to the following global variables:
	 * $GLOBALS['settings'] : current global configuration
	 * $GLOBALS['settings']['_extensions']['example'] : configuration of this extension
	 * $GLOBALS['LANG'] : the language array with translations for all languages
	 * $GLOBALS['SEEDDMS_HOOKS'] : all hooks added so far
	 */
	function init()
	{
		$GLOBALS['SEEDDMS_HOOKS']['initDMS'][] = new SeedDMS_OIDC_initDMS;
		$GLOBALS['SEEDDMS_HOOKS']['controller']['logout'][] = new SeedDMS_OIDC_Logout;
	}

	function main()
	{
	}
}

/**
 * OIDC extension
 *
 * @author  Eweol <eweol@outlook.com>
 * @package SeedDMS
 * @subpackage  OIDC
 */
class SeedDMS_OIDC_Logout
{
	/**
	 * Hook after Logout from SeedDMS
	 */
	function postLogout($logout)
	{
		$extSettings =  $logout->getParam("settings")->_extensions;
		$oidcSettings = $extSettings['oidc'];

		if (!isset($oidcSettings['oidcEnable'])) {
			return;
		}
		if ($oidcSettings['oidcEnable'] !== "1") {
			return;
		}

		$oidcServer = new SeedDMS_OIDC_Server($oidcSettings);

		$oidcServer->RedirectToOidcLogout();
		exit;
	}
}

/**
 * OIDC extension
 *
 * @author  Eweol <eweol@outlook.com>
 * @author BarnJoey <jm@salisburyit.us>
 * @package SeedDMS
 * @subpackage  OIDC
 */
class SeedDMS_OIDC_initDMS
{
	/**
	 * Hook after initializing DMS
	 */
	function postInitDMS($array)
	{

		$extSettings =  $array['settings']->_extensions;
		$settings = $array['settings'];
		$dms = $array['dms'];
		$oidcSettings = $extSettings['oidc'];

		if (!isset($oidcSettings['oidcEnable'])) {
			return;
		}
		if ($oidcSettings['oidcEnable'] !== "1") {
			return;
		}
		if (($oidcSettings['allowBypass'] ?? "0") === "1") {
			$query_string = array();
			parse_str($_SERVER['QUERY_STRING'], $query_string);
			if (($query_string["oidc_skipped"] ?? "false") === "true") {
				error_log("[Warning] OIDC bypassed to access: ".$_SERVER['REQUEST_URI']);
				return;
			}
		}
		if ($this->isExcludedURL($oidcSettings['oidcUrlExclusions'], $_SERVER['REQUEST_URI'])) {
			error_log("[Warning] URL exclusion used: ".$_SERVER['REQUEST_URI']);
			return;
		}

		if ($this->sessionIsValid()) {
			return;
		}

		$oidcServer = new SeedDMS_OIDC_Server($oidcSettings);
		if (!isset($_GET['code']) || $_GET['code'] === "") {
			if ($_GET['code'] === "") {
				$oidcServer->RedirectToOidcLogout();
				return false;
			}
			$oidcServer->RedirectToOidcLogin();
			return;
		}


		$oidcServer->GetToken($_GET["code"]);
		$jwt = new SeedDMS_OIDC_JWT($oidcServer->token->id_token);

		if (count($jwt->ClaimsArray) < 1) {
			error_log('[Critical] JWT is not Valid');
			return;
		}

		$db = $dms->getDB();
		if (!class_exists('SeedDMS_Session')) {
			require_once("./inc/inc.ClassSession.php");
		}
		if (!class_exists('SeedDMS_Controller_Login')) {
			require_once("./inc/inc.ClassControllerCommon.php");
			require_once("./controllers/class.Login.php");
		}

		$login = new SeedDMS_Controller_Login($array);

		$OidcSettings = $oidcServer->requestUserInfo();
		//OIDC settings
		$username  = $OidcSettings[$oidcServer->UsernameClaim] ?? null;
		$fullname  = $OidcSettings[$oidcServer->FullnameClaim] ?? null;
		$email     = $OidcSettings[$oidcServer->EmailClaim] ?? null;
		$roles     = $OidcSettings[$oidcServer->RoleClaim]  ?? null;
		$groups    = $OidcSettings[$oidcServer->GroupClaim] ?? null;
		
		//Check mandatory values obtained from settings
		if (empty($username)) {
			error_log('[Critical] Missing mandatory value for "username"');
			return;
		}
		if (empty($fullname)) {
			error_log('[Critical] Missing mandatory value for "fullname"');
			return;
		}
		if (empty($email)) {
			error_log('[Critical] Missing mandatory value for "email"');
			return;
		}
		
		//Other settings
		$keepUserSync = ($oidcSettings['keepUserSync'] ?? "0") === "1";
		$dmsRoles     = $this->mapClaimsArray($dms, 'role',  $roles,  $this->parseMapping($oidcSettings["roleMapping"] ?? null),  $oidcSettings);
		$dmsGroups    = $this->mapClaimsArray($dms, 'group', $groups, $this->parseMapping($oidcSettings["groupMapping"] ?? null), $oidcSettings);
		
		//Check for optional values
		if (is_null($dmsRoles) || count($dmsRoles) == 0) {
			//Let use the default 'User' role for $dms->addUser at creation
			//While updating, will keep the same value
			$userrole = 3;
		} elseif (count($dmsRoles) == 1) {
			//Both object and id are supported by $dms->addUser
			$userrole = $dmsRoles[0];
		} else {
			$strRoles = implode(", ", array_map(fn($role) : string => is_object($role) ? $role->getName() : '"'.$role.'"', $dmsRoles));
			error_log('[Critical] User with multiple roles not supported ('.$username.' -> '.$strRoles.')');
			return;
		}

		$newUser = false;
		$user = $dms->getUserByLogin($username);

		if (empty($user) && !$settings->_restricted) {
			$newUser = true;
			$user = $dms->addUser($username, null, $fullname, $email, $settings->_language, $settings->_theme, "", $userrole);
		}

		if (empty($user)) {
			error_log('[Critical] User creation failed ('.$username.')');
			return;
		}
		
		if ($newUser) {
			//Only the groups are not set
			if (!$this->updateUserGroups($user, $dmsGroups)) {
				error_log('[Critical] Unable to init groups ('.$username.' -> '.$dmsGroups.')');
				return;
			}
		} elseif ($keepUserSync) {
			//As user is denoted by its login, nonsense to keep that field in sync, will be seen as a distinct user
			/*if ($user->getLogin() != $username && !$user->setLogin($username)) {
				error_log('[Critical] Unable to update username ('.$username.')');
				return;
			}*/
			if ($user->getFullName() != $fullname && !$user->setFullName($fullname)) {
				error_log('[Critical] Unable to update full name ('.$username.')');
				return;
			}
			if ($user->getEmail() != $email && !$user->setEmail($email)) {
				error_log('[Critical] Unable to update email ('.$username.')');
				return;
			}
			//If no role was mapped, keep the default one that was given by $dms->addUser (see above)
			if (is_object($userrole) && !$this->updateUserRole($user, $userrole)) {
				error_log('[Critical] Unable to update role ('.$username.')');
				return;
			}
			if (!$this->updateUserGroups($user, $dmsGroups)) {
				error_log('[Critical] Unable to update groups ('.$username.' -> '.$dmsGroups.')');
				return;
			}
		}

		$userid = $user->getID();

		$user->clearLoginFailures();

		$lang = $user->getLanguage();
		if (strlen($lang) == 0) {
			$lang = $settings->_language;
			$user->setLanguage($lang);
		}

		$sesstheme = $user->getTheme();
		if (strlen($sesstheme) == 0) {
			$sesstheme = $settings->_theme;
			$user->setTheme($sesstheme);
		}

		$session = new SeedDMS_Session($db);

		// Delete all sessions that are more than 1 week or the configured
		// cookie lifetime old. Probably not the most
		// reliable place to put this check -- move to inc.Authentication.php?
		if ($settings->_cookieLifetime)
			$lifetime = intval($settings->_cookieLifetime);
		else
			$lifetime = 7 * 86400;
		$session->deleteByTime($lifetime);

		if (isset($_COOKIE["mydms_session"])) {
			/* This part will never be reached unless the session cookie is kept,
	         * but op.Logout.php deletes it. Keeping a session could be a good idea
	         * for retaining the clipboard data, but the user id in the session should
	         * be set to 0 which is not possible due to foreign key constraints.
	         * So for now op.Logout.php will delete the cookie as always
	         */
			/* Load session */
			$dms_session = $_COOKIE["mydms_session"];
			if (!$resArr = $session->load($dms_session)) {
				/* Turn off http only cookies if jumploader is enabled */
				setcookie("mydms_session", $dms_session, time() - 3600, $settings->_httpRoot, null, null, !$settings->_enableLargeFileUpload); //delete cookie
				header("Location: " . $settings->_httpRoot . "out/out.Login.php?referuri=" . $refer);
				exit;
			} else {
				$session->updateAccess($dms_session);
				$session->setUser($userid);
			}
		} else {
			// Create new session in database
			$id = $session->create(array('userid' => $userid, 'theme' => $sesstheme, 'lang' => $lang));

			// Set the session cookie.
			if ($settings->_cookieLifetime)
				$lifetime = time() + intval($settings->_cookieLifetime);
			else
				$lifetime = 0;
			setcookie("mydms_session", $id, $lifetime, $settings->_httpRoot, null, null, !$settings->_enableLargeFileUpload);
			$_COOKIE["mydms_session"] = $id;
		}

		$login->callHook('postLogin', $user);
	}

	private function isExcludedURL($exclusionsText, $urlCandidate)
	{
		//Used within settings.xml to separate each line from textarea
		static $linesSeparator = "~(&#13;|\R)+~";
		
		$excluded = false;
		if (is_string($exclusionsText)) {
			$exclusionLines = preg_split($linesSeparator, $exclusionsText);
			foreach($exclusionLines as $exclusionLine) {
				$regex = trim($exclusionLine);
				if (empty($regex)) {
					error_log('[Ignored] Empty exclusion pattern');
					continue;
				}
				$mayExclude = @preg_match($regex, $urlCandidate);
				if (is_null($mayExclude)) {
					error_log('[Ignored] Invalid preg_match rule ('.$regex.' '.error_get_last()["message"].')');
					continue;
				} elseif ($mayExclude) {
					$excluded = true;
					break;
				}
			}
		}
		return $excluded;
	}

	private function sessionIsValid()
	{
		return isset($_COOKIE["mydms_session"]);
	}
	
	private function parseMapping($mappingText)
	{
		//Used within settings.xml to separate each mapping line from textarea
		static $linesSeparator = "~(&#13;|\R)+~";
		//Used to separate the regex matching rule from the values to map to
		static $ruleSeparator = "=";
		//Used to separate multiple mapped values
		static $mappedsSeparator = ",";

		$mapping = array();
		if (is_string($mappingText)) {
			$mappingLines = preg_split($linesSeparator, $mappingText);
			foreach ($mappingLines as $mappingLine) {
				$mappingRule = explode($ruleSeparator, $mappingLine);
				if (count($mappingRule) != 2) {
					error_log('[Ignored] Invalid mapping definition ('.$mappingLine.')');
					continue;
				}
				
				$originalRegex = trim($mappingRule[0]);
				$regex = $originalRegex;
				if (str_starts_with($regex, "+")) {
					$regex = substr($regex, 1);
				}
				$replacements = explode($mappedsSeparator, trim($mappingRule[1]));
				if (empty($regex) || empty($replacements)) {
					error_log('[Ignored] Incomplete mapping definition ('.$mappingLine.')');
					continue;
				}
				
				$mappeds = array();
				foreach ($replacements as $replacement) {
					$mapped = trim($replacement);
					if (empty($mapped)) {
						error_log('[Ignored] Incomplete mapping definition target ('.$mappingLine.')');
						continue;
					}
					if (is_null(@preg_replace($regex, $replacement, ""))) {
						error_log('[Ignored] Invalid preg_replace rule ('.$regex.' with '.$replacement.' -> '.error_get_last()["message"].')');
						continue;
					}
					array_push($mappeds, $mapped);
				}
				$mapping[$originalRegex] = $mappeds;
			}
		}
		return $mapping;
	}
	
	private function updateUserRole($user, $role)
	{
		$fullSuccess = true;
		if (!is_null($role)) {
			if (!SeedDMS_Core_DMS::checkIfEqual($user->getRole(), $role)) {
				$fullSuccess = $user->setRole($role);
			}
		}
		return $fullSuccess;
	}
	
	private function updateUserGroups($user, $groups)
	{
		$fullSuccess = true;
		if (!is_null($groups)) {
			$toRemove = array_udiff($user->getGroups(), $groups, 'SeedDMS_OIDC_initDMS::compareDMSObjects');
			foreach ($toRemove as $group) {
				$fullSuccess &= $user->leaveGroup($group);
			}
			foreach ($groups as $group) {
				if (!$user->isMemberOfGroup($group)) {
					$fullSuccess &= $user->joinGroup($group);
				}
			}
		}
		return $fullSuccess;
	}
	
	private function mapClaimsArray($dms, $dmsType, $claimValues, $claimMapping, $oidcSettings)
	{
		$mappedValues = array();
		if (is_array($claimValues) && is_array($claimMapping)) {
			foreach ($claimValues as $claimValue) {
				$mappedValues = array_merge(
					$mappedValues,
					$this->mapClaim($dms, $dmsType, $claimValue, $claimMapping, $oidcSettings)
				);
			}
		}
		return is_null($claimValues) ? null : array_unique($mappedValues, SORT_REGULAR);
	}
	
	private function mapClaim($dms, $dmsType, $claimValue, $claimMapping, $oidcSettings)
	{
		$mappedValues = array();
		foreach ($claimMapping as $regex => $replacements) {
			$stopOnFirstMatch = true;
			if (str_starts_with($regex, "+")) {
				$stopOnFirstMatch = false;
				$regex = substr($regex, 1);
			}
			
			$nbMatches = 0;
			foreach ($replacements as $replacement) {
				$mappedValue = preg_replace($regex, $replacement, $claimValue, -1, $nbMatches);
				if ($nbMatches == 0) {
					//If first doesn't match, none with the same $claimValue/$regex will
					break;
				}
				$dmsObject = $this->getDMSObject($dms, $dmsType, $mappedValue, $oidcSettings);
				if (!is_object($dmsObject)) {
					error_log('[Ignored] None DMS '.$dmsType.' available for '.$mappedValue);
					continue;
				}
				array_push($mappedValues, $dmsObject);
			}
			
			if ($stopOnFirstMatch && $nbMatches != 0) {
				//If not on cumulative rule (default), the first match is the lone to keep
				break;
			}
		}
		return $mappedValues;
	}
	
	private function getDMSObject($dms, $dmsType, $objectNameOrId, $oidcSettings)
	{
		$dmsObject = false;
		if ($dmsType == "role") {
			$dmsObject = $this->getDMSRole($dms, $objectNameOrId, $oidcSettings);
		} elseif ($dmsType == "group") {
			$dmsObject = $this->getDMSGroup($dms, $objectNameOrId, $oidcSettings);
		}
		return $dmsObject;
	}
	
	private function getDMSRole($dms, $roleNameOrId, $oidcSettings)
	{
		//Creating role is a bit clumsy as we have to determine if this is regular, guest or admin -> won't do it so
		//But it may be one day meaningful using by exemple another settings' entry.
		$autoCreate = false;
		
		$role = false;
		$roleId = intval($roleNameOrId);
		if (is_numeric($roleNameOrId) && $roleId != 0) {
			//This is an ID, must match as we won't create a role from it
			$role = $dms->getRole($roleId);
		} else {
			//This is a role name
			$roleName = $roleNameOrId;
			$role = $dms->getRoleByName($roleName);
			if (empty($role) && $autoCreate) {
				$role = $dms->addRole($roleName, '0'); //0 stands for regular user role
			}
		}
		return $role;
	}
	
	private function getDMSGroup($dms, $groupNameOrId, $oidcSettings)
	{
		$autoCreate = ($oidcSettings['autoCreateGroups'] ?? "0") === "1";
		
		$group = false;
		$groupId = intval($groupNameOrId);
		if (is_numeric($groupNameOrId) && $groupId != 0) {
			//This is an ID, must match as we won't create a group from it
			$group = $dms->getGroup($groupId);
		} else {
			//This is a group name
			$groupName = $groupNameOrId;
			$group = $dms->getGroupByName($groupName);
			if (empty($group) && $autoCreate) {
				$group = $dms->addGroup($groupName, 'Auto-created by OIDC-Extension');
			}
		}
		return $group;
	}
	
	static function compareDMSObjects($object1, $object2)
	{
		if (is_object($object1) && is_object($object2)) {
			return $object1->getID() - $object2->getID();
		} else {
			return 0;
		}
	}
        
}

/**
 * OIDC extension
 *
 * @author  Eweol <eweol@outlook.com>
 * @author BarnJoey <jm@salisburyit.us>
 * @package SeedDMS
 * @subpackage  OIDC
 */
class SeedDMS_OIDC_Server
{
	public $Endpoint;
	public $RedirectUri;
	public $PostLogoutRedirectUri;
	public $UsernameClaim;
	public $FullnameClaim;
	public $EmailClaim;
	public $RoleClaim;
	public $GroupClaim;
	public $token;

	private $clientId;
	private $clientSecret;
	private $configuration;

	function __construct($oidcSettings)
	{
		//Mandatory fields
		$this->Endpoint      = $oidcSettings["oidcEndpoint"];
		$this->RedirectUri           = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https://" : "http://") . $_SERVER["HTTP_HOST"] . "/index.php";
		$this->PostLogoutRedirectUri = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https://" : "http://") . $_SERVER["HTTP_HOST"] . "/op/op.Logout.php";
		$this->clientId      = $oidcSettings["oidcClientId"];
		$this->clientSecret  = $oidcSettings["oidcClientSecret"];
		//Optional fields
		$this->UsernameClaim = $oidcSettings["oidcUsername"] ?? "preferred_username";
		$this->FullnameClaim = $oidcSettings["oidcFullName"] ?? "name";
		$this->EmailClaim    = $oidcSettings["oidcMail"]  ?? "email";
		$this->RoleClaim     = $oidcSettings["oidcRole"]  ?? "roles";
		$this->GroupClaim    = $oidcSettings["oidcGroup"] ?? "groups";

		$this->configuration =  $this->CurlGetJson($this->Endpoint . "/.well-known/openid-configuration");
	}

    	public function requestUserInfo(?string $attribute = null) {
        	//The accessToken has to be sent in the Authorization header.
        	// Accept json to indicate response type

        	$headers = ["Authorization: Bearer " . $this->token->access_token,
            		'Accept: application/json'];

        	$response = $this->CurlFetchJson($this->configuration->userinfo_endpoint,$headers);

        	if($attribute === null) {
            		return $response;
        	}

        	if (property_exists($response, $attribute)) {
            		return $response->$attribute;
        	}

        	return null;
    	}

	public function GetToken($code)
	{
		$data = "grant_type=authorization_code&" .
			"client_id=" . $this->clientId . "&" .
			"client_secret=" . $this->clientSecret . "&" .
			"redirect_uri=" . $this->RedirectUri . "&" .
			"code=" . $code;
		$this->token = $this->CurlPostJson($this->configuration->token_endpoint, $data);
	}

	public function RedirectToOidcLogin()
	{
		header("Location: " . $this->configuration->authorization_endpoint . "?" .
			"client_id=" . $this->clientId . "&" .
			"redirect_uri=" . $this->RedirectUri . "&" .
			"scope=openid+profile+email&" .
			"response_type=code&state=seeddms_state_notsecureatall");
	}

	public function RedirectToOidcLogout()
	{
		header("Location: " . $this->configuration->end_session_endpoint . "?" .
			"client_id=" . $this->clientId . "&" .
			"post_logout_redirect_uri=" . $this->PostLogoutRedirectUri);
	}

	private function CurlGetJson($endpoint)
	{
		$curl = curl_init();

		curl_setopt($curl, CURLOPT_HTTPGET, 1);
		curl_setopt($curl, CURLOPT_URL, $endpoint);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

		$result = curl_exec($curl);

		curl_close($curl);

		return json_decode($result);
	}

	private function CurlFetchJson($endpoint, $headers)
	{
		$curl = curl_init();

		curl_setopt($curl, CURLOPT_HTTPGET, 1);
		curl_setopt($curl, CURLOPT_URL, $endpoint);
		curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

		$result = curl_exec($curl);

		curl_close($curl);

		return json_decode($result, true);
	}

	private function CurlPostJson($endpoint, $data)
	{
		$curl = curl_init();

		curl_setopt($curl, CURLOPT_POST, 1);
		curl_setopt($curl, CURLOPT_HTTPHEADER, array(
			'Content-Type: application/x-www-form-urlencoded'
		));
		curl_setopt($curl, CURLOPT_URL, $endpoint);
		curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

		$result = curl_exec($curl);

		curl_close($curl);

		return json_decode($result);
	}
}

/**
 * OIDC extension
 *
 * @author  Eweol <eweol@outlook.com>
 * @author BarnJoey <jm@salisburyit.us>
 * @package SeedDMS
 * @subpackage  OIDC
 */
class SeedDMS_OIDC_JWT
{
	public $ClaimsArray;

	private $token;

	function __construct($jwt)
	{
		$this->token = $jwt;
		$this->getClaims();
	}

	/**
	* A wrapper around base64_decode which decodes Base64URL-encoded data,
	* which is not the same alphabet as base64.
	* @param string $base64url
	* @return bool|string
	*/
	private function base64url_decode(string $base64url) {
		return base64_decode($this->b64url2b64($base64url));
	}

	/**
	* Per RFC4648, "base64 encoding with URL-safe and filename-safe
	* alphabet".  This just replaces characters 62 and 63.  None of the
	* reference implementations seem to restore the padding if necessary,
	* but we'll do it anyway.
	* @param string $base64url
	* @return string
	*/
	private function b64url2b64(string $base64url): string
	{
		// "Shouldn't" be necessary, but why not
		$padding = strlen($base64url) % 4;
		if ($padding > 0) {
			$base64url .= str_repeat('=', 4 - $padding);
		}
		return strtr($base64url, '-_', '+/');
	}

	private function getClaims()
	{
		$tokenParts = explode('.', $this->token);

		$payload = $this->base64url_decode($tokenParts[1]);

		$this->ClaimsArray = json_decode($payload, true);
	}
}
