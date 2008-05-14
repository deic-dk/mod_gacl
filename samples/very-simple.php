<?

  // Userid/Password check
  function isvalidpassword($userid, $password) {
    return ($userid == $password);
  }

////////////////////////////////////////////////////////////////////////////////

  // $_SERVER[]
  define(PHP_AUTH_USER, "PHP_AUTH_USER");	// given userid
  define(PHP_AUTH_PW, "PHP_AUTH_PW");		// given password

  // Prompt the dialog if no password given
  if (!isset($_SERVER[PHP_AUTH_USER]) || !isset($_SERVER[PHP_AUTH_PW])) {
    header("auth-script:prompt");
    exit();
  }

  if ($_SERVER[PHP_AUTH_USER] == "") {
    header("auth-script:prompt");
    exit();
  }

  // Check the password
  if (isvalidpassword($_SERVER[PHP_AUTH_USER], $_SERVER[PHP_AUTH_PW]))
    header("auth-script:allow");
  else
    header("auth-script:prompt");

?>
