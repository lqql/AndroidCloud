<?php
header("Content-Type: text/html; charset=utf-8") ; // set the php encoding type to utf8
session_start();
$clientDHPublicKey = $_POST['clientDHPublicKey'];
$encryptAlgorithm = $_POST['encryptAlgorithm'];
exec("java ServerKeyNegotiation"." ".$clientDHPublicKey." ".$encryptAlgorithm,$out,$ret);
if((strcmp($out[sizeof($out)-1],"Error!")==0))
{
	$result_array  = array(
		'flag'=>'fail'
	);
}
else
{
	$_SESSION['sessionkey'] = $out[1];
	$sessionid = session_id();
	$result_array  = array(
		'flag'=>'success',
		'serverPubKey'=>$out[0],
		'sessionid'=>$sessionid
	);
}
echo json_encode($result_array); // encode $arr into json type
?>
