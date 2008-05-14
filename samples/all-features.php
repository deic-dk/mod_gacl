<?

  // Config
  define(EMPTY_PASSWORD_ERROR_PAGE, "/emptypassword.html");
  define(WRONG_PASSWORD_ERROR_PAGE, "/wrongpassword.html");

  // Userid/Password check
  function isvalidpassword($userid, $password) {
    return ($userid == $password);
  }

  // Canonicalize the userid
  function canonicalize($userid) {
    return strtoupper($userid);
  }

////////////////////////////////////////////////////////////////////////////////

  // $_SERVER[]
  define(PHP_AUTH_USER, "PHP_AUTH_USER");	// given userid
  define(PHP_AUTH_PW, "PHP_AUTH_PW");		// given password
  define(AUTH_SCRIPT_URI, "AUTH_SCRIPT_URI");	// the URI to be accessed.

  // Allow the error page itself.
  if ($_SERVER[AUTH_SCRIPT_URI] == EMPTY_PASSWORD_ERROR_PAGE
   || $_SERVER[AUTH_SCRIPT_URI] == WRONG_PASSWORD_ERROR_PAGE) {
    header("auth-script:allow");
    exit();
  }

  // Prompt the dialog if no password given
  if (!isset($_SERVER[PHP_AUTH_USER]) || !isset($_SERVER[PHP_AUTH_PW])) {
    header("auth-script-custom-response:" . EMPTY_PASSWORD_ERROR_PAGE);
    header("auth-script:prompt");
    exit();
  }

  if ($_SERVER[PHP_AUTH_USER] == "") {
    header("auth-script-custom-response:" . EMPTY_PASSWORD_ERROR_PAGE);
    header("auth-script:prompt");
    exit();
  }

  // Check the password
  if (isvalidpassword($_SERVER[PHP_AUTH_USER], $_SERVER[PHP_AUTH_PW])) {
    header("auth-script:allow");
    header("auth-script-user:" . canonicalize($_SERVER[PHP_AUTH_USER]));
  } else {
    header("auth-script-custom-response:" . WRONG_PASSWORD_ERROR_PAGE);
    header("auth-script:prompt");
    header("auth-script-debug:password error for... ", false);
    header("auth-script-debug:" . $_SERVER[PHP_AUTH_USER], false);
  }

?>
