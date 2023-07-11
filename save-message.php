<?php
	$name = $_POST['name'];
	$message = $_POST['message'];
	$file = fopen('messages.txt', 'a');
	fwrite($file, $name . ": " . $message . "\n");
	fclose($file);
?>