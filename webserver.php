<?php
require_once './config/config.php';
require_once 'Server.php';

set_time_limit(0);

$host = $SERVER_HOST;
$port = $SERVER_PORT;
$max_clients = 10;
$clients = array();

$sock = socket_create(AF_INET, SOCK_STREAM, 0); // master socket
socket_bind($sock, $host, $port) or die('Could not bind to address');
socket_listen($sock);

while (true) {

	$read[0] = $sock; // master socket is added to the "read" array

    	for ($i = 0; $i < $max_clients; $i++)
    	{	
        	if (isset($client[$i]['sock']))
   	    		$read[$i + 1] = $client[$i]['sock'] ;
    	}

    	$null = null;
		
    	$ready = socket_select($read,$null,$null,15);

    	if (in_array($sock, $read)) 
		{
        	for ($i = 0; $i < $max_clients; $i++)
        	{
            		if (!isset($client[$i]['sock'])) 
			{
                		$client[$i]['sock'] = socket_accept($sock);
                		break;
            		}

            		elseif ($i == $max_clients - 1)
                		print ("too many clients");
        	}

        	if (--$ready <= 0)
            		continue;

    	} // end if in_array
    
    	for ($i = 0; $i < $max_clients; $i++) // check each socket and see if they are in the 'read' array meaning if they have any read data
    	{
			
        	if (in_array($client[$i]['sock'] , $read))
        	{				
			unset($request,$input,$msg,$requests);
        		$input = socket_read($client[$i]['sock'] , 1024);
			$input = ltrim($input);
				
	    			while(trim($input) != "" && strpos($input, "\n\n") == false && strpos($input, "\r\n\r\n") == false)
				{
					$msg = $msg.$input;
					$input = socket_read($client[$i]['sock'], 1024);
				}	
								
				if($input == FALSE) // client has closed the connection
					goto socket_close;
					
				$request = empty($msg) ? $input : $msg;
								
				$p1 = "\n\n";
				$p2 = "\r\n\r\n";
				$pattern = "/".$p1."|".$p2."/";
				$requests = preg_split($pattern, $request); // usually arr[0] = request, arr[1]=\r\n  
				$request_count = count($requests);
				
				for($j = 0; $j < $request_count; $j++)
				{
					$final_request = $requests[$j];
					$k = $j+1;
					
					if(!empty($final_request))
					{						
						$webserver = new Server($final_request,$client[$i]['sock']);
						if($webserver->requestMethod() == 'POST' || $webserver->requestMethod() == 'PUT')
						{
							if($webserver->if411())
								$output = $webserver->response411();
							else
							{
								$content_length = $webserver->requestContentLength();
								$next_request = $requests[$j+1];
								
								while(strlen($next_request)!=$content_length and $k<$request_count)
								{
									$k++;
									$next_request.=$requests[$k];
								}
								
								for($r=$j;$r<$k;$r++)
								{
									unset($requests[$r]);
								}
								
								$request_entity = substr($next_request,0,$content_length);
								$webserver->setRequestEntity($request_entity);
								$output = $webserver->response();
							}
						}
						else
						{
							$output = $webserver->response();
						}	
						
						$log = $webserver->logRequest();
						unset($request,$input,$msg);
						socket_write($client[$i]['sock'], $output, strlen ($output));
						if($webserver->getConnection()=='close')
						{
							socket_close($client[$i]['sock']);
							unset($client[$i]);
							break; // if the connection prev close - then stop processing the pipelined request
						}
					}
				}

			}	
			else 
			{
            		if(isset($client[$i]['sock']))
					{
						$webserver = new Server($final_request,$client[$i]['sock']);
						$output = $webserver->response408(); // Request timed out
						$log = $webserver->logRequest();
						socket_close:
						unset($request,$input,$msg);
						socket_write($client[$i]['sock'], $output, strlen ($output));
						socket_close($client[$i]['sock']);
					}
            		unset($client[$i]);
        	}

    	}

	unset($read);
} // end while

socket_close($sock);

?>
