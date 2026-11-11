<?php
/**
 * Vulnerability probe for the PS17-SEC patch set.
 *
 * Run it against a PrestaShop 1.7 root and it reports, per vector, whether
 * that install is VULNERABLE or FIXED. The same probe runs against a pristine
 * tree and a patched tree, so the patch set is proved by the change in output
 * rather than by assertion.
 *
 * The vulnerability is in a Smarty template, not PHP logic, so the check is a
 * template analysis: does every site that renders an attacker-controllable
 * value apply an escape filter. That is weaker evidence than executing an
 * exploit, and it is labelled as such rather than dressed up.
 *
 * Usage: php probe.php /path/to/prestashop-root
 */

if ($argc < 2) {
    fwrite(STDERR, "usage: php probe.php /path/to/prestashop-root\n");
    exit(2);
}

$root = rtrim($argv[1], "/\\");

if (!is_dir($root . '/classes')) {
    fwrite(STDERR, "not a PrestaShop root: $root\n");
    exit(2);
}

$results = [];
$notes   = [];

function report($id, $vulnerable, $detail = '')
{
    global $results;
    $results[] = [$id, $vulnerable ? 'VULNERABLE' : 'FIXED', $detail];
}

function note($id, $detail = '')
{
    global $notes;
    $notes[] = [$id, $detail];
}

// ---------------------------------------------------------------------------
// CVE-2026-44212 - stored XSS in the back-office customer service view
//
// An unauthenticated visitor submits the public Contact Us form with a payload
// in the email field. It is stored, then rendered when an employee opens the
// thread. Upstream fixed it in 8.2.6 / 9.1.1 by applying the escape filter at
// the two sites that lacked it.
// ---------------------------------------------------------------------------
$tpl = $root . '/admin-dev/themes/default/template/controllers/customer_threads/helpers/view/view.tpl';

if (!is_file($tpl)) {
    report('CVE-2026-44212/template-present', true, 'customer thread view template not found');
} else {
    $lines = file($tpl, FILE_IGNORE_NEW_LINES);

    $unescaped = [];
    $escaped   = [];

    foreach ($lines as $n => $line) {
        // Every {$thread->email...} occurrence on this line, with whatever
        // filters are attached to that specific occurrence.
        if (preg_match_all('/\{\$thread->email([^}]*)\}/', $line, $m, PREG_SET_ORDER)) {
            foreach ($m as $hit) {
                $filters = $hit[1];
                $entry   = sprintf('line %d', $n + 1);

                if (strpos($filters, 'escape') !== false) {
                    $escaped[] = $entry;
                } else {
                    $unescaped[] = $entry;
                }
            }
        }
    }

    report(
        'CVE-2026-44212/thread-email-escaped',
        !empty($unescaped),
        $unescaped
            ? 'unescaped at ' . implode(', ', $unescaped)
            : 'all ' . count($escaped) . ' occurrence(s) escaped'
    );

    // Control. If this fails the probe is looking at the wrong file: the <h2>
    // near the top of this template has always been escaped, in every version.
    report(
        'CVE-2026-44212/control-h2-already-escaped',
        empty($escaped),
        $escaped ? 'escaped at ' . implode(', ', $escaped) : 'no escaped occurrence found'
    );
}

// ---------------------------------------------------------------------------
// The second half of the upstream fix, recorded as a note rather than a
// finding. Upstream switched Symfony's email validator from loose to strict.
// PrestaShop 1.7 uses egulias/EmailValidator, which has no such mode, so there
// is nothing here that a backport could flip. Reported so the gap is visible
// instead of silently absent.
// ---------------------------------------------------------------------------
$validate = $root . '/classes/Validate.php';

if (is_file($validate)) {
    $src = file_get_contents($validate);

    if (preg_match('/function isEmail.*?\n    \}/s', $src, $m)) {
        $body = $m[0];
        if (strpos($body, 'RFCValidation') !== false) {
            note('CVE-2026-44212/email-validation',
                 'egulias RFCValidation, no loose/strict mode to tighten (1.7 shape)');
        } elseif (strpos($body, "'strict'") !== false) {
            note('CVE-2026-44212/email-validation', 'Symfony validator already strict');
        } elseif (strpos($body, "'loose'") !== false) {
            note('CVE-2026-44212/email-validation',
                 'Symfony validator in loose mode, upstream tightened this');
        } else {
            note('CVE-2026-44212/email-validation', 'unrecognised isEmail implementation');
        }
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------
$vuln = 0;

foreach ($results as $r) {
    printf("%-46s %-11s %s\n", $r[0], $r[1], $r[2]);
    if ($r[1] === 'VULNERABLE') {
        $vuln++;
    }
}

printf("\n%d vector(s) VULNERABLE, %d FIXED\n", $vuln, count($results) - $vuln);

if ($notes) {
    print("\nNotes (not changed by this patch set):\n");
    foreach ($notes as $n) {
        printf("  %-44s %s\n", $n[0], $n[1]);
    }
}

exit($vuln > 0 ? 1 : 0);
