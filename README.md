# IP.Board 3 Password Driver for phpBB

Adds support for legacy Invision Power Board 3.x passwords imported in the format

```
$ipb3$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxYYYYY
```

where `xxxx...` is the MD5 password hash and `YYYYY` is the password salt.

## Installation

Copy the extension to phpBB/ext/digitalmzx/ipb3password

Go to "ACP" > "Customise" > "Extensions" and enable the "IP.Board 3 Password Driver" extension.

## License

[GNU General Public License v2](license.txt)
