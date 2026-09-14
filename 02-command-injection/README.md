# Command Injection

**Location:** `http://127.0.0.1:42001/vulnerabilities/exec/`

## What the page does

The page presents a form that asks for an IP address. On submission, the server runs `ping -c 4 <input>` and prints the raw output. When the input is passed to a shell without validation, an attacker can append their own shell commands and have them executed with the privileges of the web server.

## Setup

DVWA is running locally on Kali at port 42001. All exercises were performed against the local instance. The security level was changed between runs from the **DVWA Security** page.

---

## Low

### Source

```php
$target = $_REQUEST[ 'ip' ];
$cmd = shell_exec( 'ping  -c 4  ' . $target );
echo "<pre>{$cmd}</pre>";
```

The input is read from `$_REQUEST['ip']` and concatenated straight into `shell_exec()`. Nothing is filtered, nothing is escaped, and the resulting shell command is executed as the web server user.

### Payload

```
127.0.0.1 ; whoami ; cat /etc/passwd
```

The `;` separator runs each command independently, regardless of whether the previous one succeeded. This chains three commands: the intended ping, `whoami` to identify the web server's user account, and `cat /etc/passwd` to read the system's user account list.

### Result

The output confirmed command execution: normal ping output, followed by the username `_dvwa`, followed by the full contents of `/etc/passwd`. This proves unrestricted Remote Code Execution (RCE) at Low security.

![Low source code](screenshots/low-00-source-code.png)
![Low payload executed](screenshots/low-01-payload-executed.png)

---

## Medium

### Source

```php
$substitutions = array(
    '&&' => '',
    ';'  => '',
);
$target = str_replace( array_keys( $substitutions ), $substitutions, $target );
```

A blacklist is introduced, removing the literal strings `&&` and `;` from user input via a single-pass `str_replace()`. The filter is incomplete — it does not account for other shell metacharacters such as `|`.

### Payload

```
127.0.0.1 | whoami
```

Since `|` was never added to the blacklist, it passes through unfiltered. The pipe feeds ping's output into `whoami`, which ignores its input and simply prints the current user.

### Result

Output: `_dvwa`. The blacklist blocked `&&`/`;` successfully, but the untested `|` character bypassed it entirely, confirming command injection is still possible at Medium security.

![Medium source code](screenshots/medium-00-source-code.png)
![Medium blacklist blocks semicolon/ampersand](screenshots/medium-01-blacklist-blocks-s....png)
![Medium pipe bypass](screenshots/medium-02-pipe-bypass.png)

---

## High

### Source

```php
$target = trim($_REQUEST['ip']);
$substitutions = array(
    '||' => '',
    '&'  => '',
    ';'  => '',
    '| ' => '',
    '-'  => '',
    '$'  => '',
    '('  => '',
    ')'  => '',
    '`'  => '',
);
$target = str_replace( array_keys( $substitutions ), $substitutions, $target );
```

The blacklist is expanded to nine entries, covering more shell metacharacters. However, the pipe rule specifically targets `'| '` — a pipe **immediately followed by a space** — not the pipe character itself.

### Payloads

```
127.0.0.1|whoami
127.0.0.1 |whoami
```

Both payloads omit the space *after* the pipe, so neither matches the `'| '` pattern in the blacklist. The filter never triggers, and the pipe survives untouched in both cases.

### Result

Both payloads returned `_dvwa`, confirming that despite a much larger blacklist, a single overly-specific pattern match left an exploitable gap.

![High source code](screenshots/high-00-source-code.png)
![High pipe+space blocked](screenshots/high-01-pipe-space-blocked-p....png)
![High no-space pipe bypass](screenshots/high-02-pipe-nospace-bypass....png)

---

## Impossible

### Source

```php
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

$target = stripslashes( $_REQUEST[ 'ip' ] );
$octet = explode( ".", $target );

if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) ) {
    $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];
    $cmd = shell_exec( 'ping  -c 4  ' . $target );
    echo "<pre>{$cmd}</pre>";
} else {
    echo '<pre>ERROR: You have entered an invalid IP.</pre>';
}
```

Rather than blacklisting bad characters, this level uses a **whitelist** approach: input is split on `.` into four octets, each is validated with `is_numeric()`, and only if all four pass is a *newly rebuilt* string (not the original raw input) passed to the shell. Any injected metacharacter causes at least one octet to fail `is_numeric()`, and the request is rejected outright. A CSRF token check (`checkToken`) is also added, unrelated to the injection fix itself.

### Payload

```
127.0.0.1|whoami
```

### Result

```
ERROR: You have entered an invalid IP.
```

No command execution — the whitelist validation correctly rejects any input that isn't strictly four numeric octets separated by dots.

![Impossible source code](screenshots/impossible-00-source-code.png)
![Impossible payload rejected](screenshots/impossible-01-payload-rejecte....png)

---

## Summary

| Level | Defense | Outcome |
|---|---|---|
| Low | None | Unrestricted RCE |
| Medium | Blacklist (`&&`, `;`) | Bypassed via `\|` |
| High | Larger blacklist (`\| ` with trailing space, etc.) | Bypassed via missing space after `\|` |
| Impossible | Whitelist — strict numeric octet validation + input rebuild | Not exploitable |

**Key takeaway:** blacklisting shell metacharacters is inherently fragile — each fix in this module blocked the previously-used payload but left another variant unfiltered. Proper input validation (whitelisting an expected format, then rebuilding the value from verified components) closes the vulnerability completely.
