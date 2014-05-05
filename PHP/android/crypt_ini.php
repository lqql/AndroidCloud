<?php
class DES {
	var $key;
	function DES($key) {
		$this->key = $key;
	}
	function encrypt($input) {
		$size = mcrypt_get_block_size('des', 'ecb');
		$input = $this->pkcs5_pad($input, $size);
		$key = $this->key;
		$td = mcrypt_module_open('des', '', 'ecb', '');
		$iv = @mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
		@mcrypt_generic_init($td, $key, $iv);
		$data = mcrypt_generic($td, $input);
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);
		$data = base64_encode($data);
		return $data;
	}
	function decrypt($encrypted) {
		$encrypted = base64_decode($encrypted);
		$key =$this->key;
		$td = mcrypt_module_open('des','','ecb','');
		//使用MCRYPT_DES算法,cbc模式
		$iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
		$ks = mcrypt_enc_get_key_size($td);
		@mcrypt_generic_init($td, $key, $iv);
		//初始处理
		$decrypted = mdecrypt_generic($td, $encrypted);
		//解密
		mcrypt_generic_deinit($td);
		//结束
		mcrypt_module_close($td);
		$y=$this->pkcs5_unpad($decrypted);
		return $y;
	}
	function pkcs5_pad ($text, $blocksize) {
		$pad = $blocksize - (strlen($text) % $blocksize);
		return $text . str_repeat(chr($pad), $pad);
	}
	function pkcs5_unpad($text) {
		$pad = ord($text{strlen($text)-1});
		if ($pad > strlen($text))
			return false;
		if (strspn($text, chr($pad), strlen($text) - $pad) != $pad)
			return false;
		return substr($text, 0, -1 * $pad);
	}
}
//$key = "";
//$input = "";
//$crypt = new DES($key);
//echo "Encode:".$crypt->encrypt($input)."<br/>";
//echo "Decode:".$crypt->decrypt($crypt->encrypt($input));

//以相应的sessionid取出conversationkey
//$sessionid_4_initialize="";
session_id($sessionid_conversationkey);
session_start();
$crypt = new DES($_SESSION['conversationkey']);
session_write_close();
//保持尽可能不改变已有代码结构，生成相异于传入sessionid的新sessionid，
//以便再次创建sessionid时启用
session_start();
session_regenerate_id();
session_unset();
session_write_close();
?>
