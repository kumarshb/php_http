<?php

date_default_timezone_set('America/New_York');

// ******************* SOCKET CONFIGURATION PARAMETERS ************************

$SERVER_HOST_NAME = 'linweb';
$SERVER_HOST_FULL = 'linweb.tezirek.com';
$SERVER_PORT = 7212;
$SERVER_HOST_FULL_PORT = $SERVER_HOST_FULL.':'.$SERVER_PORT;
$SERVER_NAME = "linweb v5";
$SERVER_HOST="tezirek.com";

define("ROOT_DIR", "htdocs");
define("ROOT_DIR_NAME", "htdocs");
define("AUTH_PRIVATE_KEY", "enigmatic");
define("AUTH_PROTECT_FILE", "WeMustProtectThisHouse!");
define("URI_MAX_LIMIT", "2000");
define("ENTITY_MAX_SIZE", "2000000");

// *************** ALLOWED AND SUPPORTED METHODS FOR THIS SERVER *******************

$SUPPORTED_METHODS = array('HEAD', 'GET', 'OPTIONS', 'TRACE', 'POST', 'PUT', 'DELETE', 'CONNECT');
$ALLOWED_METHODS = array('HEAD', 'GET', 'OPTIONS', 'TRACE');

// ********** 302 REGEX AND REDIRECTS  ********************
define("regex_301_match1", "@^(.*)/dj-shadow/(.*)@");
define("regex_301_replace1", "http://djshadow.com/");
define("regex_301_match2", "@^/wsdl/$@");
define("regex_301_replace2", "http://ws-dl.blogspot.com/");
define("regex_301_match3", "@^(.*)/3/(.*)@");
define("regex_301_replace3", "$1/4/directory3isempty");

// **************** DEFAULT DIRECTORY INDEX FILE *********
define("dir_index_file", "fairlane.html");

?>
