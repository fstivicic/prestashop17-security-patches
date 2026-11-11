<?php
/**
 * Regression harness for the PS17-SEC patch set.
 *
 * probe.php asks "is this install vulnerable". It only ever looks at the
 * vulnerable construct, which means a patch could satisfy it completely and
 * still break the page. This asks the other question: does the template still
 * parse, still render, and still produce the same output for ordinary input.
 *
 * Smarty is not installed here, so the template is compiled by a minimal
 * evaluator that understands only the constructs this file uses. That is
 * enough to catch the failures that actually happen when editing a .tpl by
 * hand: a broken brace, a mangled filter chain, a quoting error inside an
 * attribute.
 *
 * Usage: php regression.php /path/to/prestashop-root
 */

if ($argc < 2) {
    fwrite(STDERR, "usage: php regression.php /path/to/prestashop-root\n");
    exit(2);
}

$root = rtrim($argv[1], "/\\");
$tpl  = $root . '/admin-dev/themes/default/template/controllers/customer_threads/helpers/view/view.tpl';

if (!is_file($tpl)) {
    fwrite(STDERR, "template not found: $tpl\n");
    exit(2);
}

$src  = file_get_contents($tpl);
$pass = 0;
$fail = 0;

function check($name, $ok, $detail = '')
{
    global $pass, $fail;

    if ($ok) {
        printf("  %-52s ok\n", $name);
        $pass++;

        return;
    }

    printf("  %-52s REGRESSION\n", $name);

    if ($detail !== '') {
        printf("      %s\n", $detail);
    }

    $fail++;
}

/**
 * Render the subset of Smarty this template uses, for one $thread->email.
 * Supports {$thread->email} with an optional |escape:'html':'UTF-8' filter.
 */
function render_email_sites($src, $email)
{
    $out = [];

    if (!preg_match_all('/\{\$thread->email([^}]*)\}/', $src, $m, PREG_SET_ORDER)) {
        return $out;
    }

    foreach ($m as $hit) {
        $filters = $hit[1];
        if (strpos($filters, 'escape') !== false) {
            $out[] = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
        } else {
            $out[] = $email;
        }
    }

    return $out;
}

echo "Template integrity\n";

// A hand-edited template most often breaks on brace balance.
check('braces balanced',
      substr_count($src, '{') === substr_count($src, '}'),
      sprintf('%d open, %d close', substr_count($src, '{'), substr_count($src, '}')));

// The Smarty block the admin theme requires must survive.
check('{block} / {/block} intact',
      substr_count($src, '{block') > 0 && substr_count($src, '{/block}') > 0);

// {if} / {/if} pairing, counting {else} as neutral.
$ifs   = preg_match_all('/\{if\s/', $src);
$endif = substr_count($src, '{/if}');
check('{if} / {/if} balanced', $ifs === $endif, sprintf('%d if, %d endif', $ifs, $endif));

// Every escape filter must carry both arguments. A half-edited filter chain
// like |escape:'html' still looks plausible and silently changes behaviour.
$bad = preg_match_all("/\|escape:'html'(?!:'UTF-8')/", $src);
check('every escape filter is complete', $bad === 0,
      $bad . " filter(s) missing the charset argument");

echo "\nOrdinary addresses still render correctly\n";

$benign = [
    'customer@example.com',
    'first.last+tag@example.co.uk',
    "o'brien@example.ie",
    'user_name-123@sub.example.com',
    'ünicode@example.com',
];

foreach ($benign as $email) {
    $rendered = render_email_sites($src, $email);

    check(
        'renders: ' . substr($email, 0, 32),
        !empty($rendered),
        'no render sites found'
    );

    // The address must still be recoverable by a reader. Escaping changes the
    // bytes but decoding must return exactly what went in.
    $ok = true;
    foreach ($rendered as $r) {
        if (html_entity_decode($r, ENT_QUOTES, 'UTF-8') !== $email) {
            $ok = false;
        }
    }

    check('  survives round trip', $ok, 'decoded output does not match input');
}

echo "\nHostile input is neutralised at every site\n";

$payloads = [
    'plain script tag'   => '<script>alert(1)</script>@example.com',
    'attribute breakout' => '" onmouseover="alert(1)',
    'single quote break' => "' onfocus='alert(1)",
    'img onerror'        => '<img src=x onerror=alert(1)>@example.com',
];

foreach ($payloads as $label => $payload) {
    $rendered = render_email_sites($src, $payload);

    $dangerous = 0;
    foreach ($rendered as $r) {
        // After rendering, no site may emit a raw angle bracket or a raw quote
        // that could terminate the surrounding attribute.
        if (strpos($r, '<') !== false || strpos($r, '>') !== false
            || strpos($r, '"') !== false || strpos($r, "'") !== false) {
            $dangerous++;
        }
    }

    check(
        'neutralised: ' . $label,
        $dangerous === 0,
        $dangerous . ' of ' . count($rendered) . ' site(s) emit raw markup'
    );
}

printf("\n%d ok, %d regressions\n", $pass, $fail);

exit($fail > 0 ? 1 : 0);
