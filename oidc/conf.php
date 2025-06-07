<?php
$EXT_CONF['oidc'] = array(
	'title' => 'OIDC Extension',
	'description' => 'This extension enables users to login via OIDC',
	'disable' => false,
	'version' => '3.0.0',
	'releasedate' => '2025-06-06',
	'author' => array( 'name'=>'BarnJoey', 'email'=>'jm@salisburyit.us', 'company'=>'SalisburyIT' ),
	'config' => array(
		'oidcEnable' => array(
			'title'=>'Enable OIDC Login',
			'type'=>'checkbox',
		),
		'allowBypass' => array(
			'title'=>'Allow to skip OIDC Login',
			'type'=>'checkbox',
		),
		'oidcEndpoint' => array(
			'title'=>'OIDC Endpoint (Required)',
			'type'=>'input',
			'required'=>'required'
		),
		'oidcClientId' => array(
			'title'=>'Client ID (Required)',
			'type'=>'input',
		),
		'oidcClientSecret' => array(
			'title'=>'Client Secret (Required)',
			'type'=>'password',
		),
		'keepUserSync' => array(
			'title'=>'Keep UserData Aligned With OIDC',
			'type'=>'checkbox',
		),
		'oidcUsername' => array(
		    'title' => 'Username Claim',
		    'type' => 'input',
			'placeholder' => "preferred_username",
		),
		'oidcMail' => array(
			'title'=>'E-Mail Claim',
		    'type'=>'input',
			'placeholder' => "email",
		),
		'oidcFullName' => array(
		    'title' => 'Fullname Claim',
		    'type' => 'input',
			'placeholder' => "name",
		),
		'oidcRole' => array(
		    'title' => 'Role Claim',
		    'type' => 'input',
			'placeholder' => "roles",
		),
		'roleMapping' => array(
		    'title' => 'Role Mapping',
		    'type' => 'textarea',
		),
		'oidcGroup' => array(
		    'title' => 'Group Claim',
		    'type' => 'input',
			'placeholder' => "groups",
		),
		'groupMapping' => array(
		    'title' => 'Group Mapping',
		    'type' => 'textarea',
		),
		'autoCreateGroups' => array(
			'title'=>'Auto-Create Groups',
			'type'=>'checkbox',
		),
		'oidcUrlExclusions' => array(
			'title' => 'Excluded URLs',
			'type' => 'textarea',
		),
	),
	'constraints' => array(
		'depends' => array('php' => '7.4.0-', 'seeddms' => '6.0.25-'),
	),
	'icon' => 'icon.svg',
	'changelog' => 'changelog.md',
	'class' => array(
		'file' => 'class.oidc.php',
		'name' => 'SeedDMS_OIDC'
	),
);
?>
