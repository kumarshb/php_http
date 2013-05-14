<?php

require_once './config/config.php';

class Server
{
	private $date = "";
	private $request = array();
	private $raw_request = "";
	private $status_code = 0;

	public function __construct($input, $socket)
	{
		global $SUPPORTED_METHODS, $ALLOWED_METHODS, $SERVER_HOST_FULL, $SERVER_PORT, $SERVER_NAME;

		socket_getpeername($socket, $address, $port);

		$this->date = gmdate("D, d M Y H:i:s")." GMT";
		$this->raw_request = $input;
		$methods_supported = implode("|", $SUPPORTED_METHODS);
		$pattern = "/(".$methods_supported.")\s+(\S+)\s+(HTTP)/";

		preg_match($pattern, $this->raw_request, $matches);
		array_shift($matches);
		list($method, $uri, $http) = $matches;
		preg_match("/Host:\s\S+/", $this->raw_request, $harr);
		list($null,$tmphost) = explode(':', $harr[0]);
		$tmphost = trim($tmphost);

		// MATCH AND FIND THE HEADERS
		preg_match("/Connection:\s[a-zA-Z]*/", $this->raw_request, $carr);
		preg_match("/HTTP\/[0-9]*\.[0-9]*/", $this->raw_request, $htar);
		preg_match("/If-Modified-Since:(.*)/", $this->raw_request, $ifm);
		preg_match("/If-Unmodified-Since:(.*)/", $this->raw_request, $iufm);
		preg_match("/If-Match:(.*)/", $this->raw_request, $ifmatch);
		preg_match("/If-None-Match:(.*)/", $this->raw_request, $ifnmatch);
		preg_match("/Accept:(.*)/", $this->raw_request, $accept_match);
		preg_match("/Accept-Charset:(.*)/", $this->raw_request, $accept_char);
		preg_match("/Accept-Encoding:(.*)/", $this->raw_request, $accept_enc);
		preg_match("/Accept-Language:(.*)/", $this->raw_request, $accept_lang);
		preg_match("/Negotiate:(.*)/", $this->raw_request, $negotiate_match);
		preg_match("/Range:(.*)/", $this->raw_request, $range_match);
		preg_match("/User-Agent:(.*)/", $this->raw_request, $user_agent_match);
		preg_match("/Referer:(.*)/", $this->raw_request, $referer_match);
		preg_match("/(Content-Length|Content-length):(.*)/", $this->raw_request, $content_length_match);
		preg_match("/(Content-Type|Content-type):(.*)/", $this->raw_request, $content_type_match);

		if(preg_match("/Authorization: Basic/", $this->raw_request) > 0)
			preg_match("/Authorization:(.*)/", $this->raw_request, $authorization);
		else
			preg_match("/Authorization:(\s)(\w+)((\s)?(\w+)[=]\"?(\w*\s?\w*\:?\/*\-?\d*\.?\=*)*\"?(\,)?)*/", $this->raw_request, $authorization);

		// EXTRACT HEADER VALUES
		list($null, $content_type) = explode(":", array_shift($content_type_match));
		list($null, $content_length) = explode(":", array_shift($content_length_match));
		list($null, $accept) = explode("Accept:", array_shift($accept_match));
		list($null, $accept_charset) = explode("Accept-Charset:", array_shift($accept_char));
		list($null, $accept_encoding) = explode("Accept-Encoding:", array_shift($accept_enc));
		list($null, $accept_language) = explode("Accept-Language:", array_shift($accept_lang));
		list($null, $negotiate_header) = explode("Negotiate:", array_shift($negotiate_match));
		list($null, $range_header) = explode("Range:", array_shift($range_match));
		list($null, $user_agent) = explode("User-Agent:", array_shift($user_agent_match));
		list($null, $referer) = explode("Referer:", array_shift($referer_match));
		list($null, $ifmod) = explode("If-Modified-Since:", array_shift($ifm));
		list($null, $ifunmod) = explode("If-Unmodified-Since:", array_shift($iufm));
		list($null, $ifmatch) = explode("If-Match:", array_shift($ifmatch));
		list($null, $ifnmatch) = explode("If-None-Match:", array_shift($ifnmatch));
		list($authorization, $auth_info) = explode("Authorization:", array_shift($authorization));
		list($null, $tmphttp) = explode('/', $htar[0]);
		list($null, $tmpconn) = explode(':', $carr[0]);

		$uri_data = parse_url($uri);
		list($null, $range_values) = explode("=", $range_header);

		$this->request['client_address'] = $address;
		$this->request['method'] = trim($method);
		$this->request['uri'] = trim($uri);
		$this->request['uri_path'] = urldecode($uri_data['path']);
		$this->request['well-known'] = $uri_data['path']=='/.well-known/access.log' ? 'well-known' : 'regular';
		$this->request['resource'] = ROOT_DIR.$this->request['uri_path'];
		$this->request['resource'] = $this->request['well-known']=='well-known' ? ROOT_DIR."/access.log" : $this->request['resource'];
		$this->request['uri_host'] = strtolower($uri_data['host']);
		$this->request['uri_scheme'] = strtolower(strtolower($uri_data['scheme']));
		$this->request['uri_query'] = $uri_data['query'];
		$this->request['host'] = $this->request['uri_scheme'] == 'http' ? $this->request['uri_host'] : $tmphost;
		$this->request['host'] = strtolower($this->request['host']);
		$this->request['connection'] = trim($tmpconn);
		$this->request['http_version'] = trim($tmphttp);
		$this->request['http_version'] = empty($this->request['http_version'])? '1.1' : $this->request['http_version'];
		$this->request['http'] = 'HTTP/';
		$this->request['date_header'] = "Date: ".$this->date."\n";
		$this->request['server_name_header'] = "Server: ".$SERVER_NAME."\n";
		$this->request['server_port'] = $SERVER_PORT;
		$this->request['hostname'] = $SERVER_HOST_FULL;
		$this->request['server_name'] = $SERVER_NAME;
		$this->request['methods_allowed'] = "Allow: ".implode(',',$ALLOWED_METHODS)."\n";
		$this->request['connection'] = empty($this->request['connection']) ? 'keep-alive' : $this->request['connection'];
		$this->request['connection_header'] = $this->request['connection']=='close' ? "Connection: ".$this->request['connection']."\n" : "";
		$this->request['last_modified'] = gmdate("D, d M Y H:i:s",filemtime($this->request['resource']))." GMT";
		$this->request['last_modified_header'] = "Last-Modified: ".$this->request['last_modified']."\n";
		$this->request['if_mod_since'] = empty($ifmod) ? 'none' : trim($ifmod);
		$this->request['if_unmod_since'] = empty($ifunmod) ? 'none' : trim($ifunmod);
		$this->request['if_match'] = empty($ifmatch) ? 'none' : trim($ifmatch);
		$this->request['if_non_match'] = empty($ifnmatch) ? 'none' : trim($ifnmatch);
		$this->request['accept_vals'] = $accept;
		$this->request['accept_char_vals'] = $accept_charset;
		$this->request['accept_lang_vals'] = $accept_language;
		$this->request['accept_enc_vals'] = $accept_encoding;
		$this->request['negotiate_vals'] = $negotiate_header;
		$this->request['range_vals'] = trim($range_values);
		$this->request['user_agent'] = $user_agent;
		$this->request['referer'] = $referer;
		$this->request['chunked_header'] = "Transfer-Encoding: chunked \n";
		$this->request['accept_ranges_header'] = "Accept-Ranges: bytes \n";
		$this->request['alternates'] = $this->getAlternates();
		$this->request['authorization_request_header'] = empty($auth_info) ? "NONE" : "Authorization";
		$this->request['authorization_info'] = $auth_info;
		$this->request['auth_opaque'] = md5($this->request['uri_path'].':'.AUTH_PRIVATE_KEY);
		$this->request['auth_stale'] = "false";
		$content_length = trim($content_length);
		$content_type = trim($content_type);
		$this->request['request_content_length'] = empty($content_length) ? "NONE" : $content_length;
		$this->request['request_content_type'] = empty($content_type) ? "NONE" : $content_type;
	}

	public function response()
	{
		global $SERVER_HOST_NAME, $SERVER_HOST_FULL, $SERVER_HOST_FULL_PORT;

		if($this->badRequest())
			return $this->response400();

		if($this->request['http_version']!='1.1')
			return $this->response505();

		return $this->response200();
	}

	public function methodsAllowed()
	{
		global $ALLOWED_METHODS;

		$methods = implode(",", $ALLOWED_METHODS);

		if($this->request['uri_path'] != "*")
		{
			if($this->putAllowed())
				$methods = $methods.","."PUT";
			if($this->deleteAllowed())
				$methods = $methods.","."DELETE";
		}

		else
		{
			$methods = $methods.",PUT,DELETE";
		}

		return $methods;
	}

	public function badRequest()
	{
		global $SERVER_HOST_NAME, $SERVER_HOST_FULL, $SERVER_HOST_FULL_PORT;

		if(empty($this->request['host']) || empty($this->request['uri']))
			return true;

		if($this->request['host'] != $SERVER_HOST_NAME && $this->request['host'] != $SERVER_HOST_FULL && $this->request['host'] != $SERVER_HOST_FULL_PORT)
			return true;

		if(preg_match_all("/Authorization: Basic/", $this->raw_request, $matches) > 1)
			return true;

		if(preg_match_all("/Authorization: Digest/", $this->raw_request,$matches) > 1)
			return true;

		if(preg_match_all("/Host:/", $this->raw_request,$matches) > 1)
			return true;

		if(preg_match_all("/Connection:/", $this->raw_request, $matches) > 1)
			return true;

		return false;
	}

	public function putAllowed()
	{
		$protect_conf_file = $this->ifProtected();

		if($protect_conf_file != "NONE")
		{
			$file_handle = fopen($protect_conf_file, "r");

			while (!feof($file_handle))
			{
				$line = fgets($file_handle);
				if(preg_match("/ALLOW-PUT/",$line) > 0)
				{
					return true;
				}
			}
		}

		return false;
	}

	public function deleteAllowed()
	{
		$protect_conf_file = $this->ifProtected();

		if($protect_conf_file != "NONE")
		{
			$file_handle = fopen($protect_conf_file, "r");
			while (!feof($file_handle)) 
			{
				$line = fgets($file_handle);
				if(preg_match("/ALLOW-DELETE/",$line) > 0)
				{
					return true;
				}
			}
		}

		return false;
	}

	public function cgiExec()
	{
		$descriptorspec = array(
		   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
		   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
		   2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
		);

		$env_referer = empty($this->request['referer']) ? "" : trim($this->request['referer']);
		$env_user_agent = empty($this->request['user_agent']) ? "" : trim($this->request['user_agent']);
		$user_id = empty($this->request['http_username']) ? "" : $this->request['http_username'];
		$cgi_input = empty($this->request['request_entity']) ? $this->request['uri_query'] : $this->request['request_entity'];

		$env = array(
		   'SERVER_NAME' => ENV_SERVER_NAME,
		   'SERVER_SOFTWARE' => ENV_SERVER_SOFTWARE,
		   'SERVER_PORT' => ENV_SERVER_PORT,
		   'SERVER_ADDR' => ENV_SERVER_ADDR,
		   'SERVER_PROTOCOL' => ENV_SERVER_PROTOCOL,
		   'SCRIPT_NAME' => $this->request['uri_path'],
		   'SCRIPT_URI' => $this->request['uri'],
		   'SCRIPT_FILENAME' => $this->request['resource'],
		   'HTTP_REFERER' => $env_referer,
		   'HTTP_USER_AGENT' => $env_user_agent,
		   'REQUEST_METHOD' => $this->request['method'],
		   'REMOTE_ADDR' => $this->request['client_address'],
		   'QUERY_STRING' => $this->request['uri_query'],
		   'REMOTE_USER' => $user_id,
		   'AUTH_TYPE' => $this->request['auth_type']
		);

		$path = escapeshellcmd($this->request['resource']);
		$process = proc_open($path, $descriptorspec, $pipes, $cwd, $env);

		if (is_resource($process)) {

			fwrite($pipes[0], $cgi_input);
			fclose($pipes[0]);

			$output = "";
			while (!feof($pipes[1])) {
				$pipe_out = fgets($pipes[1]);
				$match1 = preg_match("/_\s=\s(.*)\s<br>/",$pipe_out);
				$match2 = preg_match("/PWD\s=\s(.*)\s<br>/",$pipe_out);
				$match3 = preg_match("/SHLVL\s=\s(.*)\s<br>/",$pipe_out);
				if(($match1+$match2+$match3) == 0)
					$output = $output.$pipe_out;
			}

			fclose($pipes[1]);
			$return_value = proc_close($process);

		}

		preg_match("/Location:(.*)/", $output, $cgi_location);
		list($null,$location) = explode(":", array_shift($cgi_location));
		$location = trim($location);
		$this->request['cgi_location'] = empty($location) ? "NONE" : $location;

		preg_match("/(Content-type|Content-Type):(.*)/", $output, $cgi_content_type);
		list($null,$content_type) = explode(":", array_shift($cgi_content_type));
		$content_type = trim($content_type);
		$this->request['cgi_content_type'] = empty($content_type) ? "NONE" : $content_type;

		preg_match("/Status:(.*)/", $output, $cgi_status);
		list($null, $status) = explode(":", array_shift($cgi_status));
		$status = trim($status);
		$this->request['cgi_status'] = empty($status) ? "NONE" : $status;

		return $output;
	}

	public function if411()
	{
		if($this->requestContentLength() == "NONE" && ($this->request['method']=='POST' || $this->request['method'] = 'PUT'))
			return true;
		else
			return false;
	}

	public function setRequestEntity($entity)
	{
		$this->request['request_entity'] = $entity;
	}

	public function requestMethod()
	{
		return $this->request['method'];
	}

	public function requestContentLength()
	{
		return $this->request['request_content_length'];
	}

	public function requestContentType()
	{
		return $this->request['request_content_type'];
	}

	public function ifProtected()
	{
		$resource = $this->request['resource'];
		do
		{
			$dir = dirname($resource);
			$protect_file = $dir."/".AUTH_PROTECT_FILE;

			if(file_exists($protect_file))
			{
				return $protect_file;
			}

			$resource = $dir;
		} while($dir != ROOT_DIR);

		return "NONE";
	}

	public function protectedDomain($file)
	{
		list($null,$filename) = explode(ROOT_DIR, $file);
		$filename = trim($filename);
		return dirname($filename)."/";
	}

	public function getNonce()
	{
		$time_stamp = microtime(true);
		$nonce = base64_encode($time_stamp." ".md5($time_stamp.":".$this->getETag().":".AUTH_PRIVATE_KEY));
		$file_handle = fopen("./config/nonces", "a");
		$line = $this->request['uri_path']." ".$nonce." 00000001 \n";
		fwrite($file_handle, $line);
		fclose($file_handle);

		return $nonce;
	}

	public function digestOpaque()
	{
		return md5($this->request['uri_path'].":".AUTH_PRIVATE_KEY);
	}

	public function ifAuthorized()
	{
		$protect_config = $this->ifProtected();
		$server_auth_arr = $this->readAuthConf($protect_config);
		$this->request['auth_type'] = trim($server_auth_arr['authorization-type']);

		switch($server_auth_arr['authorization-type'])
		{
			case 'Basic':
				if(preg_match("/Basic/", $this->request['authorization_info']) < 1)
					return false; // No mention of Basic in the authorization header
				else
				{
					list($auth_type, $userinfo) = explode(" ",trim($this->request['authorization_info']));
					$userinfo = base64_decode($userinfo);
					list($username, $password) = explode(":", $userinfo);
					$h_passwd = md5($password);

					if($server_auth_arr[$username] == $h_passwd)
					{
						$this->request['http_username']=$username;
						return true;
					}
					else
						return false;
				}
				break;

			case 'Digest':
				$auth_arr = $this->parseDigest();
				$old_nonces = $this->getOldNonces();

				if(!in_array($auth_arr['nonce'], $old_nonces)) // nonces do not match still check for usernames - for stale
				{
					$a2 = $this->request['method'].':'.$auth_arr['uri'];
					$a2_hash = md5($a2);

					foreach($server_auth_arr as $key=>$value)
					{
						if($key != 'realm' and $key != 'authorization-type')
						{
							$a1_hash = $value;
							$response_digest = md5($a1_hash.':'.$auth_arr['nonce'].':'.$auth_arr['nc'].':'.$auth_arr['cnonce'].':'.$auth_arr['qop'].':'.$a2_hash);

							if($response_digest == $auth_arr['response'] and $key==$auth_arr['username'] && $auth_arr['realm'] == $server_auth_arr['realm'])
							{
								$this->request['auth_stale'] = 'true';
							}
						}
					}

					return false;
				}

				else
				{
					$a2 = $this->request['method'].':'.$auth_arr['uri'];
					$a2_hash = md5($a2);
					$this->updateNonceCount($auth_arr['nonce']);

					foreach($server_auth_arr as $key => $value)
					{
						if($key != 'realm' and $key != 'authorization-type')
						{
							$a1_hash = $value;
							$response_digest = md5($a1_hash.':'.$auth_arr['nonce'].':'.$auth_arr['nc'].':'.$auth_arr['cnonce'].':'.$auth_arr['qop'].':'.$a2_hash);
							if($response_digest == $auth_arr['response'] && $auth_arr['realm'] == $server_auth_arr['realm'] &&$auth_arr['username'] == $key)
							{
								$rspauth = md5($a1_hash.':'.$auth_arr['nonce'].':'.$auth_arr['nc'].':'.$auth_arr['cnonce'].':'.$auth_arr['qop'].':'.md5(':'.$auth_arr['uri']));
								$this->request['http_username'] = $key;
								$this->request['authentication_info'] = "Authentication-Info: ";
								$this->request['authentication_info'].= "rspauth=\"".$rspauth."\", ";
								$this->request['authentication_info'].= "qop=".$auth_arr['qop'].", ";
								$this->request['authentication_info'].= "nc=".$this->getNonceCount($auth_arr['nonce']).", ";
								$this->request['authentication_info'].= "cnonce=\"".$auth_arr['cnonce']."\"\n";
								return true;
							}
						}
					}

					return false;
				}
				break;

			default:
				return false;
				break;
		}

		return false;
	}

	public function getNonceCount($nonce_value)
	{
		$nonce_value = trim($nonce_value);
		$file_handle = fopen("./config/nonces", "r");

		while (!feof($file_handle))
		{
			$line = fgets($file_handle);

			if(trim($line) != "")
			{
				list($uri, $nonce, $ncount) = explode(" ", $line);
				$uri = trim($uri);
				$nonce = trim($nonce);
				$ncount = trim($ncount);

				if($nonce == $nonce_value)
					return $ncount;
			}
		}
		return "00000001";
	}

	public function updateNonceCount($nonce_value)
	{
		$nonce_value = trim($nonce_value);
		$file_handle = fopen("./config/nonces", "r");
		$index = 0;
		$prefix = "";

		while (!feof($file_handle))
		{
			$line = fgets($file_handle);

			if(trim($line) != "")
			{
				list($uri,$nonce,$ncount) = explode(" ",$line);
				$uri = trim($uri);
				$nonce = trim($nonce);
				$ncount = trim($ncount);

				if($nonce == $nonce_value)
				{
					$ncount = hexdec($ncount);
					$ncount++;
					$ncount = dechex($ncount);
					$suff = count(str_split($ncount));
					$zero_count = 8-$suff;

					for($i=0; $i<$zero_count; $i++)
					{
						$prefix = "0".$prefix;
					}

					$ncount = $prefix.$ncount;
					unset($prefix);
				}

				$uris[$index] = $uri;
				$nonces[$index] = $nonce;
				$ncounts[$index] = $ncount;
				$index++;
			}
		}

		fclose($file_handle);

		$file_handle = fopen("./config/nonces", "w");

		for($i = 0; $i < $index; $i++)
		{
			$newline = $i == $index ? "" : "\n";
			$line = $uris[$i]." ".$nonces[$i]." ".$ncounts[$i].$newline;
			fwrite($file_handle, $line);
		}

		fclose($file_handle);
		unset($uris, $nonces, $ncounts);
	}

	public function getOldNonces()
	{
		$file_handle = fopen("./config/nonces", "r");

		while (!feof($file_handle))
		{
			$line = fgets($file_handle);
			if(trim($line) != "")
			{
				list($uri, $nonce, $ncount) = explode(" ", $line);
				$old_nonces[] = $nonce;
			}
		}

		fclose($file_handle);
		return $old_nonces;
	}

	public function parseDigest()
	{
		$auth = explode(",", $this->request['authorization_info']);

		foreach($auth as $val)
		{
			$val = trim($val);

			if(preg_match("/username=/", $val) > 0)
			{
				list($null,$username) = explode(" ", $val);
				list($null, $auth_arr['username']) = explode("=", $username);
				$auth_arr['username'] = trim($auth_arr['username'], "\"");
			}

			if(preg_match("/realm=/", $val) > 0)
			{
				list($null,$realm) = explode("=", $val);
				$auth_arr['realm'] = trim($realm, "\"");
			}

			if(preg_match("/uri=/", $val) > 0)
			{
				list($null,$uri) = explode("=", $val);
				$auth_arr['uri'] = trim($uri, "\"");
			}

			if(preg_match("/qop=/", $val) > 0)
				list($null, $auth_arr['qop']) = explode("=", $val);

			if(preg_match("/^nonce=/", $val) > 0)
			{
				list($null,$nonce) = explode("nonce=",$val);
				$auth_arr['nonce'] = trim($nonce, "\"");
			}

			if(preg_match("/nc=/", $val) > 0)
				list($null, $auth_arr['nc']) = explode("=", $val);

			if(preg_match("/opaque=/", $val) > 0)
			{
				list($null, $opaque) = explode("=", $val);
				$auth_arr['opaque'] = trim($opaque, "\"");
			}

			if(preg_match("/cnonce=/",$val) > 0)
			{
				list($null,$cnonce) = explode("cnonce=", $val);
				$auth_arr['cnonce'] = trim($cnonce, "\"");
			}

			if(preg_match("/response=/", $val) > 0)
			{
				list($null,$response) = explode("=", $val);
				$auth_arr['response'] = trim($response, "\"");
			}
		}

		return $auth_arr;
	}

	public function readAuthConf($file)
	{
		$file_handle = fopen($file, "r");

		while (!feof($file_handle))
		{
			$line = fgets($file_handle);

			if(preg_match("/authorization-type/", $line) > 0)
			{
				list($null, $auth_type) = explode("=", $line);
				$auth_arr['authorization-type'] = trim($auth_type);
			}

			if(preg_match("/realm/", $line) > 0)
			{
				list($null,$realm) = explode("=", $line);
				$realm = trim($realm);
				$realm = trim($realm,"\"");
				$auth_arr['realm'] = trim($realm);
			}

			if(preg_match("/\:/", $line) > 0)
			{
				$user_arr=explode(":", $line);

				if(count($user_arr) > 2) //digest line
				{
					list($username, $realm, $hash) = $user_arr;
					$auth_arr[$username] = trim($hash);
				}
				else
				{
					list($username, $hash) = $user_arr;
					$auth_arr[$username] = trim($hash);
				}
			}
		}

		fclose($file_handle);

		return $auth_arr;
	}

	public function ifNoneSet($arr)
	{
		$none_set = true;

		foreach($arr as $key => $value)
		{
			if(trim($value) > '0.0')
				$none_set = false;
		}

		return $none_set;
	}

	public function getAlternates()
	{
		$alt_list = array();
		$parent_dir = dirname($this->request['resource']);
		$resource = $this->request['resource'];
		$content_encoding = $this->getContentEncoding($resource);

		if($content_encoding != 'none')
		{
			$ext = $this->encodingToExt($content_encoding);
			$resource = substr($resource,0,-(strlen($ext)));
		}

		$content_charset = $this->getContentCharset($resource);

		if($content_charset != 'none')
		{
			$ext = $this->charsetToExt($content_charset);
			$resource = $content_charset != 'none' ? substr($resource,0,-(strlen($ext))) : $resource;
		}

		$content_language = $this->getContentLanguage($resource);
		$resource = $content_language!='none' ? substr($resource, 0, -(strlen($content_language)+1)) : $resource;

		$base_name = basename($resource);
		$handle = opendir($parent_dir);

		while(($entry = readdir($handle)) != false)
		{
			$pattern = "/$base_name(.*)/";
			if(preg_match($pattern, $entry) > 0)
				$alt_list[] = $entry;
		}

		return $alt_list;
	}

	public function existImageType()
	{
		foreach($this->request['alternates'] as $source)
		{
			$resource = dirname($this->request['resource'])."/$source";
			if($this->getContentType($resource) == "image/jpeg")
				return "image/jpeg";
		}

		foreach($this->request['alternates'] as $source)
		{
			$resource = dirname($this->request['resource'])."/$source";
			if($this->getContentType($resource) == "image/gif")
				return "image/gif";
		}

		foreach($this->request['alternates'] as $source)
		{
			$resource = dirname($this->request['resource'])."/$source";
			if($this->getContentType($resource) == "image/png")
				return "image/png";
		}

		return "NONE";
	}

	public function existTextType()
	{
		foreach($this->request['alternates'] as $source)
		{
			$resource = dirname($this->request['resource'])."/$source";
			if($this->getContentType($resource) == "text/plain")
				return "text/plain";
		}

		foreach($this->request['alternates'] as $source)
		{
			$resource = dirname($this->request['resource'])."/$source";
			if($this->getContentType($resource) == "text/html")
				return "text/html";
		}

		foreach($this->request['alternates'] as $source)
		{
			$resource = dirname($this->request['resource'])."/$source";
			if($this->getContentType($resource) == "text/xml")
				return "text/xml";
		}

		return "NONE";
	}

	public function existAppType()
	{
		foreach($this->request['alternates'] as $source)
		{
			$resource = dirname($this->request['resource'])."/$source";
			if($this->getContentType($resource) == "application/pdf")
				return "application/pdf";
		}

		foreach($this->request['alternates'] as $source)
		{
			$resource = dirname($this->request['resource'])."/$source";
			if($this->getContentType($resource) == "application/vnd.ms-word")
				return "application/vnd.ms-word";
		}

		foreach($this->request['alternates'] as $source)
		{
			$resource = dirname($this->request['resource'])."/$source";
			if($this->getContentType($resource) == "application/vnd.ms-powerpoint")
				return "application/vnd.ms-powerpoint";
		}

		return "NONE";
	}

	public function getServerCharsets()
	{
		$file_handle = fopen("./config/charsets", "r");
		while (!feof($file_handle))
		{
			$line = fgets($file_handle);
			list($fext,$type) = explode(" ", $line);
			$charsets[] = trim(strtolower($type));
		}

		fclose($file_handle);
		$charsets = array_unique($charsets);
		$charsets = array_filter($charsets,"trim");

		return $charsets;
	}

	public function getServerEncodings()
	{
		$file_handle = fopen("./config/encodings", "r");
		while (!feof($file_handle))
		{
			$line = fgets($file_handle);
			list($fext, $type) = explode(" ", $line);
			$encodings[] = trim(strtolower($type));
		}

		fclose($file_handle);
		$encodings = array_unique($encodings);
		$encodings = array_filter($encodings, "trim");

		return $encodings;
	}

	public function getServerLanguages()
	{
		$file_handle = fopen("./config/languages", "r");
		while (!feof($file_handle))
		{
			$line = fgets($file_handle);
			list($fext,$type) = explode(" ",$line);
			$languages[] = trim(strtolower($type));
		}

		fclose($file_handle);
		$languages = array_unique($languages);
		$languages = array_filter($languages, "trim");

		return $languages;
	}

	public function tcnHeader()
	{
		if($this->request['tcn'] != "")
			return "TCN: ".$this->request['tcn']."\n";
		else
			return "";
	}

	public function contentLocationHeader()
	{
		if($this->request['content_location'] != "")
			return "Content-Location: ".$this->request['content_location']."\n";
		else
			return "";
	}

	public function varyHeader()
	{
		if($this->buildVary() != "negotiate")
			return "Vary: ".$this->buildVary()."\n";
		else
			return "";
	}

	public function varyMimes()
	{
		foreach($this->request['alternates'] as $alternate)
		{
			$resource = dirname($this->request['resource'])."/".$alternate;
			$type = $this->getContentType($resource);
			if($type != 'none')
				$mimes[] = $type;
		}

		return array_unique($mimes);
	}

	public function varyEncodings()
	{
		foreach($this->request['alternates'] as $alternate)
		{
			$resource = dirname($this->request['resource'])."/".$alternate;
			$encoding = $this->getContentEncoding($resource);
			if($encoding != 'none')
				$encodings[] = $encoding;
		}

		return array_unique($encodings);
	}

	public function varyLanguages()
	{
		foreach($this->request['alternates'] as $alternate)
		{
			$resource = dirname($this->request['resource'])."/".$alternate;
			$language = $this->getContentLanguage($resource);
			if($language != 'none')
				$languages[] = $language;
		}

		return array_unique($languages);
	}

	public function varyCharsets()
	{
		foreach($this->request['alternates'] as $alternate)
		{
			$resource = dirname($this->request['resource'])."/".$alternate;
			$charset = $this->getContentCharset($resource);
			if($charset != 'none')
				$charsets[] = $charset;
		}

		return array_unique($charsets);
	}

	public function buildVary()
	{
		$vary = "negotiate";

		if($this->request['content_negotiation'] == 'true')
		{
			if(count($this->varyMimes()) > 1)
				$vary = $vary.",accept";
			if(count($this->varyEncodings()) > 1)
				$vary = $vary.",accept-encoding";
			if(count($this->varyLanguages()) > 1)
				$vary = $vary.",accept-language";
			if(count($this->varyCharsets()) > 1)
				$vary = $vary.",accept-charset";
		}

		return $vary;
	}

	public function alternatesHtml()
	{
		$alternates_html = "";

		foreach($this->request['alternates'] as $alternate)
		{
			$resource = dirname($this->request['resource'])."/".$alternate;
			$alternates_html = $alternates_html."<li><a href='".urlencode($alternate)."'>$alternate</a>, type ".$this->getContentType($resource)."</li>";
		}

		return "<ul>".$alternates_html."</ul>";
	}

	public function alternatesHeader()
	{
		$alternates_field = "";
		$last = count($this->request['alternates']);
		$count = 0;
		$q = $this->request['qtie_value'] > 0 ? $this->request['qtie_value'] : '0';
		$q = $q == '1.0' ? 1 : $q;

		foreach($this->request['alternates'] as $alternate)
		{
			$count++;
			$language = $charset = $encodin ="";
			$resource = dirname($this->request['resource'])."/".$alternate;
			$charset = $this->getContentCharset($resource);
			$charset_field = $charset!='none' ? " {charset $charset} " : "";
			$language = $this->getContentLanguage($resource);
			$language_field = $language!='none' ? " {language $language} " : "";
			$encoding = $this->getContentEncoding($resource);
			$encoding_field = $encoding!='none' ? " {encoding $encoding} " : "";

			if($count != $last)
				$alternates_field = $alternates_field."{\"$alternate\" $q {type ".$this->getContentType($resource)."} $charset_field$language_field$encoding_field {length ".filesize($resource)."}},";
			else
				$alternates_field = $alternates_field."{\"$alternate\" $q {type ".$this->getContentType($resource)."} $charset_field$language_field$encoding_field {length ".filesize($resource)."}}";
		}

		return $alternates_field;
	}

	public function ifNegotiate()
	{
		if($this->request['negotiate_vals'] == '1.0')
		{
			$this->request['qtie_value'] = 1;
			return true;
		}
		else if(count($this->request['alternates']) > 0)
			return true;
		else
			return false;
	}

	public function qTies($accept_type, $map, $key, $value)
	{
		foreach($this->request['alternates'] as $alternate)
		{
			$resource = dirname($this->request['resource'])."/".$alternate;
			if($accept_type == 'accept_encoding')
				$type = $this->getContentEncoding($resource);
			else if($accept_type == 'accept_charset')
				$type = $this->getContentCharset($resource);
			else if($accept_type == 'accept_language')
				$type = $this->getContentLanguage($resource);
			else
				$type = $this->getContentType($resource);
			if($type != 'none')
				$alt_types[$type] = $alternate;
		}

		unset($map[$key]); // delete myself from the check array
		$keys_arr = array_keys($map, $value);

		foreach($keys_arr as $kkey=>$kvalue)
		{
			if(array_key_exists($kvalue, $alt_types)) // there is at least 1 with the same q value and present in the file system
			{
				$this->request['qtie_value'] = $kkey;
				return true;
			}
		}

		return false;
	}

	public function highestQ($accept_map, $type, $q)
	{
		foreach($accept_map as $key => $value)
		{
			if($key != $type)
			{
				if($value > 0)
					return false;
			}
		}
		return true;
	}

	// main function for content negotiation algorithm
	public function contentNegotiate()
	{
		$this->request['content_negotiation'] = 'true';

		if(!empty($this->request['accept_vals']))
		{
			$accept_map = $this->calcAccept("accept");

			foreach($this->request['alternates'] as $alternate)
			{
				$resource = dirname($this->request['resource'])."/".$alternate;
				$type = $this->getContentType($resource);
				$alt_types[$type] = $alternate;
			}

			foreach($accept_map as $key => $value)
			{
				if(array_key_exists($key, $alt_types)) // candidate with the highest q value is present in the alternates so return and quit loop
				{
					if($this->qTies("accept", $accept_map, $key, $value))
					{
						$this->request['qtie_value'] = $value;
						return $this->response300('accept'); // q value ties  - return 300
					}

					else // we have a winner for 200
					{
						$this->request['resource'] = dirname($this->request['resource'])."/".$alt_types[$key];
						$this->request['content_location'] = $alt_types[$key];
						$this->request['tcn'] = "choice";
						return $this->response200();
					}
				}

				else
				{
					if($this->highestQ($accept_map, $key, $value))
					{
						return $this->response406('accept');
						break;
					}
					else
						unset($accept_map[$key]);
				}
			}
		}

		if(!empty($this->request['accept_char_vals']))
		{
			$accept_map = $this->calcAccept("accept_charset");

			foreach($this->request['alternates'] as $alternate)
			{
				$resource = dirname($this->request['resource'])."/".$alternate;
				$charset = $this->getContentCharset($resource);
				$alt_chars[$charset] = $alternate;
			}

			foreach($accept_map as $key => $value)
			{
				if(array_key_exists($key, $alt_chars)) // candidate with the highest q value is present in the alternates so return and quit loop
				{
					if($this->qTies("accept_charset", $accept_map, $key, $value))
					{
						$this->request['qtie_value'] = $value;
						return $this->response300('accept_charset'); // q value ties  - return 300
					}

					else // we have a winner for 200
					{
						$this->request['resource'] = dirname($this->request['resource'])."/".$alt_chars[$key];
						$this->request['content_location'] = $alt_chars[$key];
						$this->request['tcn'] = "choice";
						return $this->response200();
					}
				}

				else
				{
					if($this->highestQ($accept_map,$key,$value))
					{
						return $this->response406('accept_charset');
						break;
					}
					else
						unset($accept_map[$key]);
				}
			}

		}

		if(!empty($this->request['accept_enc_vals']))
		{
			$accept_map = $this->calcAccept("accept_encoding");

			foreach($this->request['alternates'] as $alternate)
			{
				$resource = dirname($this->request['resource'])."/".$alternate;
				$encoding = $this->getContentEncoding($resource);
				$alt_encs[$encoding] = $alternate;
			}

			foreach($accept_map as $key => $value)
			{
				if(array_key_exists($key, $alt_encs)) // candidate with the highest q value is present in the alternates so return and quit loop
				{
					if($this->qTies("accept_encoding", $accept_map, $key, $value))
					{
						$this->request['qtie_value'] = $value;
						return $this->response300('accept_encoding'); // q value ties  - return 300
					}

					else // we have a winner for 200
					{
						$this->request['resource'] = dirname($this->request['resource'])."/".$alt_encs[$key];
						$this->request['content_location'] = $alt_encs[$key];
						$this->request['tcn'] = "choice";
						return $this->response200();
					}
				}

				else
				{
					if($this->highestQ($accept_map, $key, $value))
					{
						return $this->response406('accept_encoding');
						break;
					}
					else
						unset($accept_map[$key]);
				}
			}

		}

		if(!empty($this->request['accept_lang_vals']))
		{
			$accept_map = $this->calcAccept("accept_language");

			foreach($this->request['alternates'] as $alternate)
			{
				$resource = dirname($this->request['resource'])."/".$alternate;
				$language = $this->getContentLanguage($resource);
				$alt_langs[$language] = $alternate;
			}

			foreach($accept_map as $key => $value)
			{
				if(array_key_exists($key, $alt_langs)) // candidate with the highest q value is present in the alternates so return and quit loop
				{
					if($this->qTies("accept_language", $accept_map, $key, $value))
					{
						$this->request['qtie_value'] = $value;
						return $this->response300('accept_language'); // q value ties  - return 300
					}
					else // we have a winner for 200
					{
						$this->request['resource'] = dirname($this->request['resource'])."/".$alt_langs[$key];
						$this->request['content_location'] = $alt_langs[$key];
						$this->request['tcn'] = "choice";
						return $this->response200();
					}
				}

				else
				{
					if($this->highestQ($accept_map, $key, $value))
					{
						return $this->response406('accept_language');
						break;
					}
					else
						unset($accept_map[$key]);
				}
			}
		}

		return $response=$this->response300();
	}

	public function calcAccept($accept_type)
	{
		switch($accept_type)
		{
			case 'accept':
				$accept_map = array();
				$csv_accept_arr = explode(',', $this->request['accept_vals']);

				foreach($csv_accept_arr as $key)
				{
					list($mime,$weight) = explode(';',$key);
					$mime = trim($mime);
					list($null, $weight) = explode('=', trim($weight));

					if(preg_match("/\//",$mime) > 0)
					{
						list($mtype,$stype) = explode("/", $mime);
					}
					else
					{
						$mtype = $stype = "*";
					}

					if($stype != "*")
					{
						$accept_map[$mime] = $weight;
					}

					else // subtype is * eg : image/* , text/* etc
					{
						switch($mtype)
						{
							case 'image':
								$accept_map['image/jpeg'] = array_key_exists('image/jpeg',$accept_map) ? $accept_map['image/jpeg'] : $weight;
								$accept_map['image/png'] = array_key_exists('image/png',$accept_map) ? $accept_map['image/png'] : $weight;
								$accept_map['image/gif'] = array_key_exists('image/gif',$accept_map) ? $accept_map['image/gif'] : $weight;
								break;

							case 'text':
								$accept_map['text/plain'] = array_key_exists('text/plain',$accept_map) ? $accept_map['text/plain'] : $weight;
								$accept_map['text/html'] = array_key_exists('text/html',$accept_map) ? $accept_map['text/html'] : $weight;
								$accept_map['text/xml'] = array_key_exists('text/xml',$accept_map) ? $accept_map['text/xml'] : $weight;
								break;

							case 'application':
								$accept_map['application/pdf'] = array_key_exists('application/pdf',$accept_map) ? $accept_map['application/pdf'] : $weight;
								$accept_map['application/vnd.ms-powerpoint'] = array_key_exists('application/vnd.ms-powerpoint',$accept_map) ? $accept_map['application/vnd.ms-powerpoint']:$weight;
								$accept_map['application/vnd.ms-word'] = array_key_exists('application/vnd.ms-word',$accept_map) ? $accept_map['application/vnd.ms-word']:$weight;
								break;

							case '*': // any file is OK since we have */* q=weight; format
								$accept_map['image/jpeg'] = array_key_exists('image/jpeg',$accept_map) ? $accept_map['image/jpeg'] : $weight;
								$accept_map['image/png'] = array_key_exists('image/png',$accept_map) ? $accept_map['image/png'] : $weight;
								$accept_map['image/gif'] = array_key_exists('image/gif',$accept_map) ? $accept_map['image/gif'] : $weight;
								$accept_map['text/plain'] = array_key_exists('text/plain',$accept_map) ? $accept_map['text/plain'] : $weight;
								$accept_map['text/html'] = array_key_exists('text/html',$accept_map) ? $accept_map['text/html'] : $weight;
								$accept_map['text/xml'] = array_key_exists('text/xml',$accept_map) ? $accept_map['text/xml'] : $weight;
								$accept_map['application/pdf'] = array_key_exists('application/pdf',$accept_map) ? $accept_map['application/pdf']:$weight;
								$accept_map['application/vnd.ms-powerpoint'] = array_key_exists('application/vnd.ms-powerpoint',$accept_map) ? $accept_map['application/vnd.ms-powerpoint']:$weight;
								$accept_map['application/vnd.ms-word'] = array_key_exists('application/vnd.ms-word',$accept_map) ? $accept_map['application/vnd.ms-word']:$weight;
						}
					}
				}

				arsort($accept_map);
				return $accept_map;
				break;

			case 'accept_charset':
				$accept_map = array();
				$csv_accept_arr = explode(',',$this->request['accept_char_vals']);

				foreach($csv_accept_arr as $key)
				{
					list($charset, $weight) = explode(';', $key);
					$charset = trim($charset);
					list($null, $weight) = explode('=', trim($weight));

					if($charset != '*')
					{
						$accept_map[$charset] = $weight;
					}
					else
					{
						$charsets = $this->getServerCharsets();
						foreach($charsets as $charset)
						{
							$accept_map[$charset] = array_key_exists($charset,$accept_map) ? $accept_map[$charset] : $weight;
						}
					}
				}

				arsort($accept_map);
				return $accept_map;
				break;

			case 'accept_encoding':
				$accept_map = array();
				$csv_accept_arr = explode(',',$this->request['accept_enc_vals']);

				foreach($csv_accept_arr as $key)
				{
					list($encoding,$weight) = explode(';', $key);
					$encoding = trim($encoding);
					list($null,$weight) = explode('=', trim($weight));

					if($encoding != '*')
					{
						$accept_map[$encoding] = $weight;
					}
					else
					{
						$encodings = $this->getServerEncodings();
						foreach($encodings as $encoding)
						{
							$accept_map[$encoding] = array_key_exists($encoding,$accept_map) ? $accept_map[$encoding] : $weight;
						}
					}
				}

				arsort($accept_map);
				return $accept_map;
				break;

			case 'accept_language':
				$accept_map = array();
				$csv_accept_arr = explode(',', $this->request['accept_lang_vals']);

				foreach($csv_accept_arr as $key)
				{
					list($language,$weight) = explode(';', $key);
					$language = trim($language);
					list($null, $weight) = explode('=', trim($weight));

					if($language != '*')
					{
						$accept_map[$language] = $weight;
					}
					else
					{
						$languages = $this->getServerLanguages();
						foreach($languages as $language)
						{
							$accept_map[$language] = array_key_exists($language,$accept_map) ? $accept_map[$language] : $weight;
						}
					}
				}

				arsort($accept_map);
				return $accept_map;
				break;

			default:
				return null;
				break;
		}

	}

	public function fileLastModHeader($file)
	{
		$lmdate = gmdate("D, d M Y H:i:s",filemtime($file))." GMT";
		$lmheader = "Last-Modified: ".$lmdate."\n";

		return $lmheader;
	}

	public function getConnection()
	{
		return $this->request['connection'];
	}

	public function chunkMsg($msg)
	{
		$splits = explode("\n",$msg);
		$splits = array_filter($splits,"trim");

		for($i = 1; $i <= count($splits); $i+=2)
		{
			$result[$i] = $splits[$i]."\n".$splits[$i+1];
		}

		foreach($result as $line)
		{
			$line = trim($line);
			if(!empty($line))
				$output = $output.dechex(strlen($line))."\n".$line."\r\n\r\n";
		}

		return $output."0 \r\n\r\n";;
	}

	public function logRequest()
	{
		$log_dir = ROOT_DIR."/access.log";
		$user_id = empty($this->request['http_username']) ? "-" : $this->request['http_username'];
		$file_handle = fopen($log_dir,"a");
		$log = $this->request['client_address']." - ".$user_id." [".date("d/M/Y:H:i:s O")."] \"".$this->request['method']." ".$this->request['uri']." ";
		$log = $log.$this->request['http'].$this->request['http_version']."\" ".$this->request['status_code']." ";
		$filesize = is_file($this->request['resource']) ? filesize($this->request['resource']) : 0;
		$filesize = $this->request['dynamic_size']==0 ? 0 : $this->request['dynamic_size'];
		$log = $log.$filesize;
		$this->request['referer'] = empty($this->request['referer']) ? "-" : "\"".trim($this->request['referer'])."\"";
		$this->request['user_agent'] = empty($this->request['user_agent']) ? "-" : "\"".trim($this->request['user_agent'])."\"";
		$log = $log." ".$this->request['referer'];
		$log = $log." ".$this->request['user_agent']."\n";

		fwrite($file_handle,$log);
		fclose($file_handle);
	}

	public function encodingToExt($encoding)
	{
		$encoding = trim($encoding);
		$file_handle = fopen("./config/encodings", "r");

		while (!feof($file_handle))
		{
			$line = fgets($file_handle);
			list($fext, $type) = explode(" ", $line);
			$type = trim($type);
			if(strcmp($encoding, $type) == 0)
				return trim($fext);
		}

		fclose($file_handle);
	}

	public function charsetToExt($charset)
	{
		$charset = trim($charset);
		$file_handle = fopen("./config/charsets", "r");

		while (!feof($file_handle))
		{
			$line = fgets($file_handle);
			list($fext, $type) = explode(" ", $line);
			$type = strtolower(trim($type));
			if(strcmp($charset, $type) == 0)
				return trim($fext);
		}

		fclose($file_handle);
	}

	public function getContentType($resource = "")
	{
		$resource = empty($resource) ? $this->request['resource'] : $resource;
		$content_encoding = $this->getContentEncoding($resource);

		if($content_encoding != 'none')
		{
			$ext = $this->encodingToExt($content_encoding);
			$resource = substr($resource,0,-(strlen($ext)));
		}

		$content_charset = $this->getContentCharset($resource);

		if($content_charset != 'none')
		{
			$ext = $this->charsetToExt($content_charset);
			$resource = $content_charset != 'none' ? substr($resource,0,-(strlen($ext))) : $resource;
		}

		$content_language = $this->getContentLanguage($resource);
		$resource = $content_language != 'none' ? substr($resource,0,-(strlen($content_language)+1)) : $resource;

		$ext = pathinfo($resource, PATHINFO_EXTENSION);
		$ext = ".".$ext;
		$file_handle = fopen("./config/mimes", "r");

		while (!feof($file_handle))
		{
			$line = fgets($file_handle);
			list($fext, $type) = explode(" ", $line);
			$fext = trim($fext);
			$type = trim($type);
			if(strcmp($ext, $fext) == 0)
				return trim($type);
		}

		fclose($file_handle);

		if(is_dir($this->request['resource']))
			return "text/html";
		else
			return "text/plain";
	}

	public function contentCharsetHeader($resource="")
	{
		$charset = $this->getContentCharset($resource);
		$charset_field = $charset == "none" ? "" : "; charset=$charset";

		return $charset_field;
	}

	public function getContentCharset($resource = "")
	{
		$resource = empty($resource) ? $this->request['resource'] : $resource;
		$ext = pathinfo($resource,PATHINFO_EXTENSION);
		$ext = ".".$ext;
		$file_handle = fopen("./config/charsets", "r");

		while (!feof($file_handle))
		{
			$line = fgets($file_handle);
			list($fext,$type) = explode(" ",$line);
			$fext = trim($fext);
			$type = trim($type);
			if(strcmp(strtolower($ext), strtolower($fext)) == 0)
				return trim(strtolower($type));
		}

		fclose($file_handle);
		return "none";
	}

	public function contentLanguageHeader($resource = "")
	{
		$resource = empty($resource) ? $this->request['resource'] : $resource;
		$content_language = $this->getContentLanguage($resource);
		$content_language_header = $content_language == "none" ? "" : "Content-Language: $content_language \n";

		return $content_language_header;
	}

	public function getContentLanguage($resource = "")
	{
		$resource = empty($resource) ? $this->request['resource'] : $resource;
		$content_encoding = $this->getContentEncoding($resource);

		if($content_encoding != 'none')
		{
			$ext = $this->encodingToExt($content_encoding);
			$resource = substr($resource,0,-(strlen($ext)));
		}

		$content_charset = $this->getContentCharset($resource);

		if($content_charset != 'none')
		{
			$ext = $this->charsetToExt($content_charset);
			$resource = $content_charset!='none' ? substr($resource,0,-(strlen($ext))) : $resource;
		}

		$ext = pathinfo($resource,PATHINFO_EXTENSION);
		$ext = ".".$ext;
		$file_handle = fopen("./config/languages", "r");

		while (!feof($file_handle))
		{
			$line = fgets($file_handle);
			list($fext,$type) = explode(" ", $line);
			$fext = trim($fext);
			$type = trim($type);

			if(strcmp($ext, $fext) == 0)
				return trim($type);
		}

		fclose($file_handle);
		return "none";
	}

	public function contentEncodingHeader($resource = "")
	{
		$resource = empty($resource) ? $this->request['resource'] : $resource;
		$content_encoding = $this->getContentEncoding($resource);
		$content_encoding_header = $content_encoding=="none" ? "" : "Content-Encoding: $content_encoding \n";
		return $content_encoding_header;
	}

	public function getContentEncoding($resource = "")
	{
		$resource = empty($resource) ? $this->request['resource'] : $resource;
		$ext = pathinfo($resource,PATHINFO_EXTENSION);
		$ext = ".".$ext;
		$file_handle = fopen("./config/encodings", "r");

		while (!feof($file_handle))
		{
			$line = fgets($file_handle);
			list($fext,$type) = explode(" ", $line);
			$fext = trim($fext);
			$type = trim($type);
			if(strcmp($ext, $fext) == 0)
				return trim($type);
		}

		fclose($file_handle);
		return "none";
	}

	public function isExecutable()
	{
		$perms = fileperms($this->request['resource']);

		if (($perms & 0xC000) == 0xC000) {
			// Socket
			$info = 's';
		} elseif (($perms & 0xA000) == 0xA000) {
			// Symbolic Link
			$info = 'l';
		} elseif (($perms & 0x8000) == 0x8000) {
			// Regular
			$info = '-';
		} elseif (($perms & 0x6000) == 0x6000) {
			// Block special
			$info = 'b';
		} elseif (($perms & 0x4000) == 0x4000) {
			// Directory
			$info = 'd';
		} elseif (($perms & 0x2000) == 0x2000) {
			// Character special
			$info = 'c';
		} elseif (($perms & 0x1000) == 0x1000) {
			// FIFO pipe
			$info = 'p';
		} else {
			// Unknown
			$info = 'u';
		}

		// Owner
		$info .= (($perms & 0x0100) ? 'r' : '-');
		$info .= (($perms & 0x0080) ? 'w' : '-');
		$info .= (($perms & 0x0040) ?
					(($perms & 0x0800) ? 's' : 'x' ) :
					(($perms & 0x0800) ? 'S' : '-'));
		// Group
		$info .= (($perms & 0x0020) ? 'r' : '-');
		$info .= (($perms & 0x0010) ? 'w' : '-');
		$info .= (($perms & 0x0008) ?
					(($perms & 0x0400) ? 's' : 'x' ) :
					(($perms & 0x0400) ? 'S' : '-'));
		// World
		$info .= (($perms & 0x0004) ? 'r' : '-');
		$info .= (($perms & 0x0002) ? 'w' : '-');
		$info .= (($perms & 0x0001) ?
					(($perms & 0x0200) ? 't' : 'x' ) :
					(($perms & 0x0200) ? 'T' : '-'));

		if(substr($info,-1) == 'x' or substr($info, -4, 1) == 'x')
			return true;
		else
			return false;
	}

	public function isForbidden()
	{
		$perms = fileperms($this->request['resource']);

		if (($perms & 0xC000) == 0xC000) {
			// Socket
			$info = 's';
		} elseif (($perms & 0xA000) == 0xA000) {
			// Symbolic Link
			$info = 'l';
		} elseif (($perms & 0x8000) == 0x8000) {
			// Regular
			$info = '-';
		} elseif (($perms & 0x6000) == 0x6000) {
			// Block special
			$info = 'b';
		} elseif (($perms & 0x4000) == 0x4000) {
			// Directory
			$info = 'd';
		} elseif (($perms & 0x2000) == 0x2000) {
			// Character special
			$info = 'c';
		} elseif (($perms & 0x1000) == 0x1000) {
			// FIFO pipe
			$info = 'p';
		} else {
			// Unknown
			$info = 'u';
		}

		// Owner
		$info .= (($perms & 0x0100) ? 'r' : '-');
		$info .= (($perms & 0x0080) ? 'w' : '-');
		$info .= (($perms & 0x0040) ?
					(($perms & 0x0800) ? 's' : 'x' ) :
					(($perms & 0x0800) ? 'S' : '-'));
		// Group
		$info .= (($perms & 0x0020) ? 'r' : '-');
		$info .= (($perms & 0x0010) ? 'w' : '-');
		$info .= (($perms & 0x0008) ?
					(($perms & 0x0400) ? 's' : 'x' ) :
					(($perms & 0x0400) ? 'S' : '-'));
		// World
		$info .= (($perms & 0x0004) ? 'r' : '-');
		$info .= (($perms & 0x0002) ? 'w' : '-');
		$info .= (($perms & 0x0001) ?
					(($perms & 0x0200) ? 't' : 'x' ) :
					(($perms & 0x0200) ? 'T' : '-'));

		if(substr($info,-3,1)=='-')
			return true;
		else
			return false;
	}

	public function directoryListing()
	{
		$top_html = "<h4>Index of ".$this->request['uri_path']."</h4>Name Last Modified Size Description<hr> \n";
		$handle = opendir($this->request['resource']);

		while(($entry = readdir($handle)) != false)
		{
			$entry_link = $this->request['uri_path'].$entry; // link to the resource
			$full_link = ROOT_DIR.$entry_link;
			unset($entry_size, $entry_logo, $entry_modif_date);

			if(is_dir($entry_link))
			{
				$entry_size = "-";
				$entry_logo = "";
				$entry_modif_date = gmdate("d-M-Y H:i",filemtime($full_link));
			}

			else
			{
				$entry_size = filesize($full_link);
				$entry_logo = "";
				$entry_modif_date = gmdate("d-M-Y H:i",filemtime($full_link));
			}

			if($entry != "." and $entry != ".well-known")
			{
				if($entry == '..')
				{
					$html = $html."<a href='../'>Parent Directory</a><br> \n";
				}
				else
				{
					$html = $html."$entry_logo <a href='$entry_link'>$entry</a> &nbsp;&nbsp;&nbsp;$entry_modif_date &nbsp;&nbsp; $entry_size <br> \n";
				}
			}
		}

		return $top_html.$html;
	}

	public function getETag()
	{
		$fs = stat(dirname($this->request['resource']));
		$etag = sprintf('%x-%x-%s', $fs['ino'], $fs['size'],base_convert(str_pad($fs['mtime'],16,"0"),10,16));
		$fs = stat(dirname($this->request['resource'])."/".$this->request['content_location']);
		$vlv = sprintf('%x-%x-%s', $fs['ino'], $fs['size'],base_convert(str_pad($fs['mtime'],16,"0"),10,16));

		$this->request['ETag']=$this->request['tcn']=='choice' ? $this->request['ETag']=$vlv.";".$etag : $etag;

		return $this->request['ETag'];
	}

	public function calcReadRange()
	{
		$file_length = filesize($this->request['resource']);
		list($range1,$range2) = explode("-",$this->request['range_vals']);

		if(trim($range1) > $file_length && trim($range2) > 0)
		{
			$this->request['status_code'] = 416;
		}

		else
		{
			if(trim($range1) == "" && trim($range2) != "") // first range is missing
			{
				$end = $file_length - 1;
				$start = $file_length-intval($range2);
			}
			else if(trim($range1) != "" && trim($range2) == "") // second range is missing
			{
				$start = intval($range1);
				$end = $file_length - 1;
			}

			else if(trim($range1) != "" && trim($range2) != "") //both present
			{
				$start = intval($range1);
				$end = intval($range2);
			}

			$end = $end > $file_length ? ($file_length-1) : $end;
		}

		return array($start,$end);
	}

	private function testPre200()
	{
		$rcode = array();
		$response = 200;

		if(strlen($this->request['request_entity']) > ENTITY_MAX_SIZE)
			return $this->response413();

		if(strlen($this->request['uri']) > URI_MAX_LIMIT)
			return $this->response414();

		if($this->ifProtected() != 'NONE' and !($this->ifAuthorized())) // protection!=none = protected resource
			return $this->response401();

		if(preg_match(regex_301_match1, $this->request['uri_path']) || preg_match(regex_301_match2,$this->request['uri_path']) || preg_match(regex_301_match3, $this->request['uri_path']))
			$response = $this->response301();

		else if(!file_exists($this->request['resource']) && !is_dir($this->request['resource']))
			$response = $this->response404();

		else if($this->isForbidden())
			$response = $this->response403();

		// ********************************** CONDITIONALS AND LOGIC ***************************************************************

		else if($this->request['if_mod_since'] != 'none' and strtotime($this->request['if_mod_since']) >= strtotime($this->request['last_modified']))
		{
			$rcode[] = 304; // not modified since
		}

		else if($this->request['if_unmod_since']!='none' and strtotime($this->request['if_unmod_since'])<strtotime($this->request['last_modified']))
		{
			$rcode[] = 412;
		}

		else if($this->request['if_match'] != 'none')
		{
			$stripped_etag = preg_replace("/\"/","", $this->request['if_match']);
			$etag_array = explode(",",$stripped_etag);

			foreach($etag_array as $etag)
			{
				if(trim($this->getETag())==trim($etag))
				   $if_match=true;
			}

			$rcode[]=$if_match!=true ? 412 : 200;
		}

		else if($this->request['if_non_match']!='none')
		{
			$stripped_etag=preg_replace("/\"/","",$this->request['if_non_match']);
			$etag_array=explode(",",$stripped_etag);
			foreach($etag_array as $etag)
			{
				if(trim($this->getETag())==trim($etag))
					$if_non_match=false; // precondition failed - 304/412  - for later when other methods will be implemented should be issued
			}

			$rcode[]=$if_non_match==false ? 304 : 200;
		}
				
		else
			$response="200";

		array_unique($rcode); // remove extra 200's and 412's

		if(in_array(304,$rcode))
			$response=$this->response304();
			
		else if(in_array(412,$rcode))
			$response=$this->response412();

		else if(!empty($this->request['range_vals']))
			$response=$this->response206();
			
		else
			$response=$response;
			
		return $response;
	}

    // ************************************** ALL THE 200-5xx RESPONSE FUNCTIONS ****************************************************/

	public function response200($direct = "false")
	{
		$index_file = $this->request['resource'].dir_index_file; // default directory index file
		$this->request['status_code'] = 200;
		$test_pre200 = 200; // for additionals

		switch($this->request['method'])
		{
			case 'GET':
				if($direct == "false")
					$test_pre200 = $this->testPre200(); // do 404 and other related tests prior to handling 200
				if($test_pre200 != '200')
					return $test_pre200;

				if($this->isExecutable())
				{
					$cgi_output = $this->cgiExec();
					if($this->request['cgi_location']!="NONE")
						return $this->response302($this->request['cgi_location']);

					$status = $this->request['cgi_status']=='NONE' ? "200 OK" : $this->request['cgi_status'];
					$content_type = $this->request['cgi_content_type']=='NONE' ? "text/plain" : $this->request['cgi_content_type'];
					$response = $this->request['http'].$this->request['http_version']." ".$status." \n"; // same for dir and files
					$response = $response.$this->request['date_header']; // same for dir and files
					$response = $response.$this->request['server_name_header']; // same for dir and files
					$response = $response.$this->request['authentication_info'];
					$response = $response."Content-Length: ".strlen($cgi_output)."\n";
					$response = $response.$this->request['connection_header'];
					$response = $response."Content-Type: ".$content_type."\r\n\r\n";
					$response = $response.$cgi_output."\r\n";
				}

				else
				{
					$response = $this->request['http'].$this->request['http_version']." 200 OK \n"; // same for dir and files
					$response = $response.$this->request['date_header']; // same for dir and files
					$response = $response.$this->request['server_name_header']; // same for dir and files
					$response = $response.$this->request['authentication_info'];
					$response = $response.$this->contentLocationHeader();
					$response = $response.$this->varyHeader();
					$response = $response.$this->tcnHeader();

					// DIRECTORY
					if(is_dir($this->request['resource']))
					{
						if(substr($this->request['resource'],-1) != '/' and $test_pre200 == 200)
							return $this->response301();

						else if(file_exists($index_file)) // default dir index file exists
						{
							$this->request['resource'] = $index_file;
							$response = $response.$this->fileLastModHeader($index_file);
							$response = $response."ETag: \"".$this->getETag()."\"\n";
							$response = $response.$this->request['accept_ranges_header'];
							$response = $response."Content-Length: ".filesize($this->request['resource'])."\n";
							$response = $response.$this->request['connection_header'];
							$response = $response.$this->contentLanguageHeader($this->request['resource']);
							$response = $response.$this->contentEncodingHeader($this->request['resource']);
							$response = $response."Content-Type: ".$this->getContentType()."\r\n\r\n";
							$response = $response.file_get_contents($this->request['resource'])."\r\n";
						}
						else
						{
							$html = $this->directoryListing();
							$html = $this->chunkMsg($html);
							$response = $response."ETag: \"".$this->getETag()."\"\n";
							$response = $response.$this->request['connection_header'];
							$response = $response.$this->request['chunked_header'];
							$response = $response."Content-Type: ".$this->getContentType()."\r\n\r\n";
							$response = $response.$html."\r\n";
						}
					}
					// REGULAR FILE
					else
					{
						$response = $response.$this->request['last_modified_header'];
						$response = $response."ETag: \"".$this->getETag()."\"\n";
						$response = $response.$this->request['accept_ranges_header'];
						$response = $response."Content-Length: ".filesize($this->request['resource'])."\n";
						$response = $response.$this->request['connection_header'];
						$response = $response.$this->contentLanguageHeader();
						$response = $response.$this->contentEncodingHeader();
						$response = $response."Content-Type: ".$this->getContentType().$this->contentCharsetHeader()."\r\n\r\n";
						$response = $response.file_get_contents($this->request['resource'])."\r\n";
					}
				}
				break;

			case 'HEAD':
				if($direct == "false")
					$test_pre200=$this->testPre200(); // do 404 and other related tests prior to handling 200

				if($this->isExecutable() and $test_pre200!='200')
				{
					$cgi_output = $this->cgiExec();
					if($this->request['cgi_location']!="NONE")
						return $this->response302($this->request['cgi_location']);

					$status = $this->request['cgi_status']=='NONE' ? "200 OK" : $this->request['cgi_status'];
					$content_type = $this->request['cgi_content_type']=='NONE' ? "text/plain" : $this->request['cgi_content_type'];
					$response = $this->request['http'].$this->request['http_version']." ".$status." \n"; // same for dir and files
					$response = $response.$this->request['date_header']; // same for dir and files
					$response = $response.$this->request['server_name_header']; // same for dir and files
					$response = $response.$this->request['authentication_info'];
					$response = $response."Content-Length: ".strlen($cgi_output)."\n";
					$response = $response.$this->request['connection_header'];
					$response = $response."Content-Type: ".$content_type."\r\n\r\n";
				}

				else
				{
					if($test_pre200 != '200')
						return $test_pre200;

					$response = $this->request['http'].$this->request['http_version']." 200 OK \n";
					$response = $response.$this->request['date_header'];
					$response = $response.$this->request['server_name_header'];
					$response = $response.$this->request['authentication_info'];
					$response = $response.$this->contentLocationHeader();
					$response = $response.$this->varyHeader();
					$response = $response.$this->tcnHeader();

					// DIRECTORY
					if(is_dir($this->request['resource']))
					{
						if(substr($this->request['resource'],-1) != '/' and $test_pre200 == 200)
							return $this->response301();

						else if(file_exists($index_file)) // default dir index file exists
						{
							$this->request['resource'] = $index_file;
							$response = $response.$this->fileLastModHeader($index_file);
							$response = $response."ETag: \"".$this->getETag()."\"\n";
							$response = $response.$this->request['accept_ranges_header'];
							$response = $response."Content-Length: ".filesize($this->request['resource'])."\n";
							$response = $response.$this->request['connection_header'];
							$response = $response.$this->contentLanguageHeader();
							$response = $response.$this->contentEncodingHeader();
							$response = $response."Content-Type: ".$this->getContentType()."\r\n\r\n";
						}
						else
						{
							$html = $this->directoryListing();
							$response = $response."ETag: \"".$this->getETag()."\"\n";
							$response = $response.$this->request['connection_header'];
							$response = $response.$this->request['chunked_header'];
							$response = $response."Content-Type: ".$this->getContentType()."\r\n\r\n";
						}
					}
					// REGULAR FILE
					else
					{
						$response = $response.$this->request['last_modified_header'];
						$response = $response."ETag: \"".$this->getETag()."\"\n";
						$response = $response.$this->request['accept_ranges_header'];
						$response = $response."Content-Length: ".filesize($this->request['resource'])."\n";
						$response = $response.$this->request['connection_header'];
						$response = $response.$this->contentLanguageHeader();
						$response = $response.$this->contentEncodingHeader();
						$response = $response."Content-Type: ".$this->getContentType().$this->contentCharsetHeader()."\r\n\r\n";
					}
				}
				break;

			case 'OPTIONS':
				if($direct == "false" and trim($this->request['uri_path']) != '*')
					$test_pre200 = $this->testPre200(); // do 404 and other related tests prior to handling 200

				if($test_pre200 == '200')
				{
					$response = $this->request['http'].$this->request['http_version']." 200 OK \n";
					$response = $response.$this->request['date_header'];
					$response = $response.$this->request['server_name_header'];
					$response = $response.$this->request['accept_ranges_header'];
					$response = $response."Allow: ".$this->methodsAllowed()."\n";
					$response = $response."Content-Length: 0 \n";
					$response = $response.$this->request['connection_header'];
					$response = $response.$this->contentLanguageHeader($this->request['resource']);
					$response = $response.$this->contentEncodingHeader($this->request['resource']);
					$response = $response."Content-Type: message/http \r\n\r\n";

					return $response;
				}
				break;

			case 'TRACE':
				$response = $this->request['http'].$this->request['http_version']." 200 OK \n";
				$response = $response.$this->request['date_header'];
				$response = $response.$this->request['server_name_header'];
				$response = $response.$this->request['connection_header'];
				$response = $response."Content-Length: ".strlen(ltrim($this->raw_request))."\n";
				$response = $response."Content-Type: message/http \r\n\r\n";
				$response = $response.ltrim($this->raw_request);
				$response = $response."\r\n";
				break;

			case 'POST':
				if($direct == "false")
					$test_pre200 = $this->testPre200(); // do 404 and other related tests prior to handling 200

				if($test_pre200 == '200')
				{
					if(!$this->isExecutable())
						return $this->response405();

					$cgi_output = $this->cgiExec();
					if($this->request['cgi_location'] != "NONE")
						return $this->response302($this->request['cgi_location']);

					$status = $this->request['cgi_status']=='NONE' ? "200 OK" : $this->request['cgi_status'];
					$content_type = $this->request['cgi_content_type'] == 'NONE' ? "text/plain" : $this->request['cgi_content_type'];
					$response = $this->request['http'].$this->request['http_version']." ".$status." \n"; // same for dir and files
					$response = $response.$this->request['date_header']; // same for dir and files
					$response = $response.$this->request['server_name_header']; // same for dir and files
					$response = $response.$this->request['authentication_info'];
					$response = $response."Content-Length: ".strlen($cgi_output)."\n";
					$response = $response.$this->request['connection_header'];
					$response = $response."Content-Type: ".$content_type."\r\n\r\n";
					$response = $response.$cgi_output."\r\n";

				}
				break;

			case 'PUT':
				if($direct == "false")
					$test_pre200 = $this->testPre200(); // do 404 and other related tests prior to handling 200

				if($test_pre200 == '200')
				{
					if($this->putAllowed())
					{
						// modify an existent resource
						if(file_exists($this->request['resource']))
						{
							$file_handle = fopen($this->request['resource'],"w");
							$content_length = strlen($this->request['request_entity']);
							fwrite($file_handle,$this->request['request_entity'],$content_length);
							fclose($file_handle);

							$response_html = "
							<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
							<html><head><title>The resource was updated</title></head><body>
							The resource ".$this->request['resource']."has been sucessfully updated
							<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
							"<address></body></html>"."\r\n";

							$response_html = preg_replace('/\t+/', ' ',$response_html);
							$response_html = $this->chunkMsg($response_html);
							$response = $this->request['http'].$this->request['http_version']." 200 OK \n"; // same for dir and files
							$response = $response.$this->request['date_header']; // same for dir and files
							$response = $response.$this->request['server_name_header']; // same for dir and files
							$response = $response."Content-Length: ".strlen($html)."\n";
							$response = $response.$this->request['connection_header'];
							$response = $response."Content-Type: text/html \r\n\r\n";
							$response = $response.$response_html."\r\n";
						}
						else
						{
							$file_handle = fopen($this->request['resource'],"w");
							$content_length = strlen($this->request['request_entity']);
							fwrite($file_handle,$this->request['request_entity'],$content_length);
							fclose($file_handle);
							$this->request['resource_location'] = $this->request['uri_path'];
							$response = $this->response201();
						}
					}
					else
					{
						return $this->response405();
					}

				}

				break;

			case 'DELETE':
				if($direct == "false")
					$test_pre200 = $this->testPre200(); // do 404 and other related tests prior to handling 200

				if($test_pre200 == '200' and $this->request['status_code'] != '401')
				{
					if($this->deleteAllowed())
					{
						unlink($this->request['resource']);

						$html = "Delete was sucessful";
						$response = $this->request['http'].$this->request['http_version']." 200 OK \n";
						$response = $response.$this->request['date_header'];
						$response = $response.$this->request['server_name_header'];
						$response = $response.$html;
					}
					else
					{
						return $this->response405();
					}
				}
				break;

			default:
				$response = $this->response501();
				break;
		}

		return $test_pre200 == '200' ? $response : $test_pre200;
	}


	public function response201()
	{
		$this->request['resource'] = ROOT_DIR.$this->request['resource_location'];
		$response_html = "
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>201 Created</title></head><body>
		The resource ".$this->request['resource']."has been sucessfully created
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html = preg_replace('/\t+/', ' ',$response_html);
		$html = $this->chunkMsg($html);
		$this->request['dynamic_size'] = strlen($html);
		$this->request['status_code'] = 201;
		$body=$this->request['method'] == 'HEAD' ? "" : $html;

		$response = $this->request['http'].$this->request['http_version']." 201 Created \n"; // same for dir and files
		$response = $response.$this->request['date_header']; // same for dir and files
		$response = $response.$this->request['server_name_header']; // same for dir and files
		$response = $response."Location: ".$this->request['resource_location']."\n";
		$response = $response."Content-Length: ".strlen($html)."\n";
		$response = $response.$this->request['connection_header'];
		$response = $response."Content-Type: text/html \r\n\r\n";
		$response = $response.$body."\r\n";

		return $response;
	}

	public function response206()
	{
		list($start,$end) = $this->calcReadRange();

		if($this->request['status_code'] != 416)
		{
			$length = ($end-$start) + 1;
			$partial_content = file_get_contents($this->request['resource'], NULL, NULL, $start, $end);
			$body = $this->request['method'] == 'HEAD' ? "" : $partial_content;
			$this->request['status_code'] = 206;
			$response = $this->request['http'].$this->request['http_version']." 206 Partial Content \n"; // same for dir and files
			$response = $response.$this->request['date_header']; // same for dir and files
			$response = $response.$this->request['server_name_header']; // same for dir and files
			$response = $response.$this->contentLocationHeader();
			$response = $response.$this->varyHeader();
			$response = $response.$this->tcnHeader();
			$response = $response.$this->request['last_modified_header'];
			$response = $response."ETag: \"".$this->getETag()."\"\n";
			$response = $response.$this->request['accept_ranges_header'];
			$response = $response."Content-Length: ".$length."\n";
			$response = $response."Content-Range: bytes $start-$end/".filesize($this->request['resource'])."\n";
			$response = $response.$this->request['connection_header'];
			$response = $response.$this->contentLanguageHeader();
			$respose = $response.$this->contentEncodingHeader();
			$response = $response."Content-Type: ".$this->getContentType().$this->contentCharsetHeader()."\r\n\r\n";

			$response = $response.$body."\r\n";
		}
		else
		{
			$response=$this->response416();
		}

		return $response;
	}

	// ******************** DYNAMIC RESPONSE ****************************************************************************

	public function response300($accept_type="")
	{
		$alternates_html=$this->alternatesHtml();

		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>300 Multiple Choices</title></head><body>
		<h1>300 Multiple choices</h1>
		<p>Available variants are : </p><br>
		$alternates_html
		
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=300;
		$body=$this->request['method']=='HEAD' ? "" : $html;
		$response=$this->request['http'].$this->request['http_version']." 300 Multiple Choices \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response."Alternates: ".$this->alternatesHeader()."\n";
		$response=$response."Vary: ".$this->buildVary()."\n";
		$response=$response."TCN: list \n";
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;
		
		return $response;
	}
	
	public function response301()
	{
		if(preg_match(regex_301_match1,$this->request['uri_path']))
		{
			$location=regex_301_replace1;
		}
		
		else if(preg_match(regex_301_match2,$this->request['uri_path']))
		{
			$location=regex_301_replace2;
		}
		
		else if(preg_match(regex_301_match3,$this->request['uri_path']))
		{
			$match3=preg_replace(regex_301_match3,regex_301_replace3,$this->request['uri_path']);
			$match3=str_replace("%2F","/",urlencode($match3));
			$location="http://".$this->request['hostname'].':'.$this->request['server_port'].$match3;
		}
		else		
			$location="http://".$this->request['hostname'].':'.$this->request['server_port'].$this->request['uri_path'].'/';
		
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>301 Moved Permanently</title></head><body>
		<h1>Moved Permanently</h1>
		<p>The document has moved <a href='$location'>here</a>.
		</p><br>
		<hr>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=301;
		$body=$this->request['method']=='HEAD' ? "" : $html;
		$response=$this->request['http'].$this->request['http_version']." 301 Moved Permanently \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response."Location: ".$location."\n";
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;
		
		return $response;
	}
	
	public function response302($location="")
	{
		if($location=="")
		{
			if(preg_match(regex_302_match1,$this->request['uri_path']))
			{
				$match1=preg_replace(regex_302_match1,regex_302_replace1,$this->request['uri_path']);
				$match1=str_replace("%2F","/",urlencode($match1));

				$location="http://".$this->request['hostname'].':'.$this->request['server_port'].$match1;
			}
			else
			{
				$match2=preg_replace(regex_302_match2,regex_302_replace2,$this->request['uri_path']);
				$match2=str_replace("%2F","/",urlencode($match2));
				$location="http://".$this->request['hostname'].':'.$this->request['server_port'].$match2;
			}
		}
		else
			$location=$location;
		
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>302 Found</title></head><body>
		<h1>302 Found</h1>
		<p>The document has a new temporary location <a href='$location'>here</a>.
		</p><br>
		<hr>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=302;
		$body=$this->request['method']=='HEAD' ? "" : $html;
		$response=$this->request['http'].$this->request['http_version']." 302 Found \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response."Location: ".$location."\n";
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;
		
		return $response;
	}
	
	public function response304()
	{

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=0;
		$this->request['status_code']=304;
		$response=$this->request['http'].$this->request['http_version']." 304 Not Modified \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response."ETag: \"".$this->getETag()."\"\n";
		$response=$response."Content-Length: 0 \n";
		$response=$response.$this->request['connection_header'];
		$response=$response."Content-Type: text/plain \r\n\r\n";

		return $response;

	}
		
	public function response400()
	{	
		$this->request['connection']='close'; // since it is a bad request "force" connection close - do not continue in case of pipelined requests
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>400 Bad Request</title></head><body>
		<h1>Bad Request</h1>
		<p>Your browser sent a request that this server could not understand</p><br>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=400;
		$body=$this->request['method']=='HEAD' ? "" : $html;
		$response=$this->request['http'].$this->request['http_version']." 400 Bad Request \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response."Connection: ".$this->request['connection']."\n";
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;
		
		return $response;
	}
	
	public function response401()
	{
		$protect_config=$this->ifProtected();
		$server_auth_arr=$this->readAuthConf($protect_config);

		if($this->request['auth_type']=='Basic')
		{
			$this->request['www-authenticate']="WWW-Authenticate: Basic realm=\"".$server_auth_arr['realm']."\"\n";
		}
		else
		{
			$this->request['www-authenticate']="WWW-Authenticate: Digest realm=\"".$server_auth_arr['realm']."\", ";
			$this->request['www-authenticate'].="domain=\"".$this->protectedDomain($protect_config)."\", ";
			$this->request['www-authenticate'].="qop=\"auth,auth-int\", ";
			$this->request['www-authenticate'].="nonce=\"".$this->getNonce()."\", ";
			$this->request['www-authenticate'].="algorithm=\"MD5\", ";
			$this->request['www-authenticate'].="stale=\"".$this->request['auth_stale']."\", ";
			$this->request['www-authenticate'].="opaque=\"".$this->digestOpaque()."\" \n";								
		}
	
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head>
		<title>401 Authorization Required</title>
		</head><body>
		<h1>401 Authorization Required </h1>
		<p>This server could not verify that you are authorized to access the document requested.  Either you supplied the wrong
		credentials (e.g., bad password), or your browser doesn't understand how to supply the credentials required.</p>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";
		
		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=401;
		$body=$this->request['method']=='HEAD' ? "" : $html;
		$response=$this->request['http'].$this->request['http_version']." 401 Authorization Required\n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response.$this->request['www-authenticate'];
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;				
		return $response;
		
	}

	public function response403()
	{
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head>
		<title>403 Forbidden</title>
		</head><body>
		<h1>403 Forbidden</h1>
		<p>You don't have permission to access ".$this->request['uri_path']." on this server.</p>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";
		
		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=403;
		$body=$this->request['method']=='HEAD' ? "" : $html;
		$response=$this->request['http'].$this->request['http_version']." 403 Forbidden\n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;

		return $response;
	}

	
	public function response404()
	{	
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head>
		<title>404 Not Found</title>
		</head><body>
		<h1>404 Not Found</h1>
		<p>The requested URL ".$this->request['uri_path']." was not found on this server.</p>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";
		
		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=404;
		$body=$this->request['method']=='HEAD' ? "" : $html;
		$response=$this->request['http'].$this->request['http_version']." 404 Not Found \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;

		if($this->ifNegotiate())
			$response=$this->contentNegotiate();
		
		return $response;
	}
	
	public function response405()
	{
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>405 Method Not Allowed</title></head><body>
		<h1>405 Method Not Allowed</h1>
		<p>This method ".$this->request['method']." on the request for the URL ".$this->request['uri_path']." is not allowed
		</p><br>
		<hr>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=405;
		$response=$this->request['http'].$this->request['http_version']." 405 Method Not Allowed \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response."Allow: ".$this->methodsAllowed()."\n";
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$html;
		
		return $response;
	
	}
		
	public function response406()
	{
		$alternates_html=$this->alternatesHtml();
		
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>406 Not Acceptable</title></head><body>
		<h1>406 Not Acceptable</h1>
		<p> An appropriate representation of the requested resource".$this->request['resource']."could not be found on this server </p>
		<p>Available variants are : </p><br>
		$alternates_html
		
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=406;
		$body=$this->request['method']=='HEAD' ? "" : $html;
		$response=$this->request['http'].$this->request['http_version']." 406 Not Acceptable \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response."Alternates: ".$this->alternatesHeader()."\n";
		$response=$response."Vary: ".$this->buildVary()."\n";
		$response=$response."TCN: list \n";
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;
		
		return $response;
	}
	
	
	public function response408()
	{
		$this->request['connection']='close'; // since it is a bad request "force" connection close - do not continue in case of pipelined requests
		
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>408 Request Timed Out</title></head><body>
		<h1>Request Timed Out</h1>
		<p>The server timed out while trying to service the client connection.</p><br>\n
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=408;
		$body=$html;
		$response=$this->request['http'].$this->request['http_version']." 408 Request Timed Out \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response."Connection: ".$this->request['connection']."\n";
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;
		
		return $response;

	}
	
	public function response411()
	{
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>411 Length Required</title></head><body>
		<h1>411 Length Required</h1>
		<p>
		Entity length is required with this request
		</p><br>
		<hr>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=411;
		$response=$this->request['http'].$this->request['http_version']." 411 Length Required \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$html;
		
		return $response;
	
	}
	
	public function response412()
	{
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>412 Precondition Failed</title></head><body>
		<h1>Precondition Failed</h1>
		<p>The Precondtion on the request for the URL ".$this->request['uri_path']." evaluated to false
		</p><br>
		<hr>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=412;
		$body=$this->request['method']=='HEAD' ? "" : $html;
		$response=$this->request['http'].$this->request['http_version']." 412 Precondition Failed \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;
		
		return $response;

	}

	public function response413()
	{
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>413 Request Entity Too Large</title></head><body>
		<h1>413 Request Entity Too Large</h1>
		<p>
		Request Entity Too Large for this request
		</p><br>
		<hr>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=413;
		$response=$this->request['http'].$this->request['http_version']." 413 Request Entity Too Large \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$html;
		
		return $response;
	
	}
	
	public function response414()
	{
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head><title>414 Request-URI Too Long</title></head><body>
		<h1>414 Request-URI Too Long</h1>
		<p>
		The Request-URI Too Long for this request
		</p><br>
		<hr>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";

		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=414;
		$response=$this->request['http'].$this->request['http_version']." 414 Request-URI Too Long \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response.$this->request['connection_header'];
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$html;
		
		return $response;
	
	}
	
	public function response416()
	{
		$this->request['dynamic_size']=0;
		$this->request['status_code']=416;
		$response=$this->request['http'].$this->request['http_version']." 416 Requested Range Not Satisfiable \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response.$this->request['last_modified_header'];
		$response=$response."ETag: \"".$this->getETag()."\"\n";
		$response=$response.$this->request['accept_ranges_header'];
		$response=$response."Content-Length: 0 \n";
		$response=$response."Content-Range: bytes */".filesize($this->request['resource'])."\n";
		$response=$response.$this->request['connection_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		
		return $response;	
	}
	
	public function response501()
	{
		$this->request['connection']='close'; // since it is a bad request "force" connection close - do not continue in case of pipelined requests

		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head>
		<title>501 Method Not Implemented</title>
		</head><body>
		<h1>Method Not Implemented</h1>
		<p>".$this->request['method']." to ".$this->request['uri_path']." not supported.<br />
		</p><address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";
		
		$html=preg_replace('/\t+/', ' ',$html);		
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$this->request['status_code']=501;
		$body=$this->request['method']=='HEAD' ? "" : $html;
		$response=$this->request['http'].$this->request['http_version']." 501 Not Implemented \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response.$this->request['methods_allowed'];
		$response=$response."Connection: ".$this->request['connection']."\n";
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;

		return $response;
	}

	public function response505()
	{
		$this->request['connection']='close'; // since it is a bad request "force" connection close - do not continue in case of pipelined requests
		
		$html="
		<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
		<html><head>
		<title>505 HTTP Version Not Supported</title>
		</head><body>
		<h1>505 HTTP Version Not Supported</h1>
		This server does not support the HTTP version ".$this->request['http_version']."
		<br>
		Please use HTTP/1.1 instead </br>
		<address>".$this->request['server_name']." at ".$this->request['hostname']." port ".$this->request['server_port'].
		"<address></body></html>"."\r\n";
		
		$html=preg_replace('/\t+/', ' ',$html);
		$html=$this->chunkMsg($html);
		$this->request['dynamic_size']=strlen($html);
		$body=$this->request['method']=='HEAD' ? "" : $html;
		$this->request['status_code']=505;
		$response=$this->request['http']."1.1 505 HTTP Version Not Supported \n";
		$response=$response.$this->request['date_header'];
		$response=$response.$this->request['server_name_header'];
		$response=$response."Connection: ".$this->request['connection']."\n";
		$response=$response.$this->request['chunked_header'];
		$response=$response."Content-Type: text/html \r\n\r\n";
		$response=$response.$body;

		return $response;
	}


}
?>
