<?php declare(strict_types=1);
/**
 *
 * IP.Board 3 Password Driver. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2023, Lachesis, https://www.digitalmzx.com/
 * @license GNU General Public License, version 2 or later (GPL-2.0-or-later)
 *
 */

namespace digitalmzx\ipb3password;

/**
 * Invision Power Board 3 password driver.
 *
 * IPB 3.x uses a password hash in the following form: md5(md5(salt) . md5(pass)).
 * Unfortunately, Invision did something extremely silly and used a sanitized
 * copy of the password, so an equivalent sanitizer needs to be run here too.
 *
 * Password hashes are stored in the format
 *
 *   $ipb3$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxYYYYY
 *
 * where 'xxxx...' is the MD5 password hash and 'YYYYY' is the password salt.
 */
class password_ipb3 extends \phpbb\passwords\driver\base
{
	const PREFIX = '$ipb3$';

	const REPLACEMENTS =
	[
		// Ampersand first so it doesn't interfere with the other rules.
		'/\&/'			=> '&amp;',

		// Special cases that need to go before the general case rules.
		'/<!--/'		=> '&#60;&#33;--',
		'/-->/'			=> '--&#62;',
		'/<script/i'	=> '&#60;script',

		// Everything else:
		'/</'			=> '&lt;',
		"/>/"			=> '&gt;',
		'/\n/'			=> '<br />',
		'/"/'			=> '&quot;',
		"/'/" 			=> '&#39;',
		'/!/'			=> '&#33;',
		'/\$/'			=> '&#036;',
		'/\r/'			=> '',
	];

	/**
	 * Perform the equivalent of IPB 3.x's input sanitization routine.
	 *
	 * @param string $str an unsanitized string.
	 * @return string a string, sanitized in the manner of IPB 3.x
	 */
	protected static function sanitize_ipb3_string(string $str): string
	{
		return preg_replace(array_keys(self::REPLACEMENTS), self::REPLACEMENTS, $str) ?? '';
	}

	/**
	 * Reverse phpBB 3.1+'s password sanitization routine. phpBB uses
	 * htmlspecialchars() with ENT_COMPAT on the password for no good reason,
	 * which is reversable by replacing &quot; with ". phpBB would need to add
	 * compatibility checks to all of their password drivers to change the
	 * sanitization again, so this should be stable.
	 *
	 * The phpBB 2.x driver uses $_REQUEST['password'] instead. For some
	 * reason, the phpBB 3.0 driver doesn't perform the same conversion.
	 *
	 * @param string $str a phpBB sanitized password string.
	 * @return string the original unsanitized string.
	 */
	protected static function unsanitize_phpbb_string(string $str): string
	{
		return str_replace('&quot;', '"', $str);
	}

	/**
	 * {@inheritdoc}
	 */
	public function get_prefix()
	{
		return self::PREFIX;
	}

	/**
	 * {@inheritdoc}
	 */
	public function is_legacy()
	{
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function hash($password, $user_row = [])
	{
		// Do NOT make new IPB 3.x password hashes :(
		return false;
	}

	/**
	 * {@inheritdoc}
	 */
	public function check($password, $hash, $user_row = [])
	{
		if (!is_string($password) || !is_string($hash) || strlen($hash) != 43)
		{
			return false;
		}

		$salt = substr($hash, 6 + 32);
		$hash = substr($hash, 6, 32);

		$password = self::unsanitize_phpbb_string($password);
		$password = self::sanitize_ipb3_string($password);

		return strcmp($hash, md5(md5($salt) . md5($password))) == 0;
	}
}
