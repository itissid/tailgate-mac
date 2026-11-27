"""Offline vocabulary generation tests. Never rewrite the checked-in atlas."""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('atlas_vocabulary', ROOT / 'Scripts/atlas-vocabulary.py')
atlas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(atlas)
CSS = (ROOT / 'Docs/atlas-terms-ui.css').read_text()
JS = (ROOT / 'Docs/atlas-terms-ui.js').read_text()
TERMS = '''# Canonical vocabulary
**Read-only client**: The OAuth client used to read policy. It cannot write. This is not part of the short definition.
**Policy writer**: The distinct OAuth client that can write policy.
**Client credentials**: The client ID and secret used to obtain an access token.
**Access token**: A short-lived bearer credential issued by OAuth.
**Setup record**: The protected configuration item containing setup data.
**Node public-key pin**: The independently verified identity of the intended node.
**Signing identity**: The identity used to sign app code, not the node key.
**Write outcome**: The result reported for the policy write.
**Scope**: The permissions requested from OAuth.
**Review fingerprint**: The SHA-256 digest of the review text.
**Keychain item**: One stored Keychain object.
'''


def document(body):
    return '<!doctype html><html><head><title>reader</title></head><body><main>' + body + '</main></body></html>'


def render(source, terms=TERMS):
    return atlas.generate(source, terms, CSS, JS)[0]


def annotated(source):
    return re.findall(r'data-term="([^"]+)"[^>]*>([^<]*)</(?:span|tspan)>', source.split(atlas.START)[0])


class AtlasVocabularyTests(unittest.TestCase):
    def test_canonical_markdown_and_first_two_sentences(self):
        terms = atlas.definitions(TERMS)
        self.assertEqual(terms['read-only-client']['definition'], 'The OAuth client used to read policy. It cannot write.')
        terms = atlas.definitions('- **Extra term:** An `inline` [label](local.md). Another sentence. Third sentence.\n')
        self.assertEqual(terms['extra-term']['definition'], 'An inline label. Another sentence.')
        self.assertEqual(atlas.definitions('**Extra term**:\n  First sentence.\n  Second sentence.\n\nUnrelated.' )['extra-term']['definition'], 'First sentence. Second sentence.')
        with self.assertRaises(ValueError):
            atlas.definitions('No canonical vocabulary yet.')
        with self.assertRaises(ValueError):
            atlas.definitions('**Same**: First.\n**Same**: Conflicting.')
        with self.assertRaises(ValueError):
            atlas.definitions('```\n**Fake**: Not a canonical entry.\n```')

    def test_prose_tables_captions_and_inline_code(self):
        source = document('<p>The reader client uses a reader token. A writer client emits <code>write_outcome</code>.</p><table><caption>Setup record</caption><tr><td>Keychain item</td><td>configuration item</td></tr></table>')
        output = render(source)
        self.assertEqual(annotated(output), [
            ('read-only-client', 'reader client'), ('access-token', 'reader token'),
            ('policy-writer', 'writer client'), ('write-outcome', 'write_outcome'),
            ('setup-record', 'Setup record'), ('keychain-item', 'Keychain item'),
            ('setup-record', 'configuration item')])
        self.assertEqual(atlas.clean(output), source)

    def test_longest_matches_and_no_substrings_or_wrong_identity(self):
        source = document('<p>OAuth reader token, writer bearer, writer secret, writer client; write_outcome. Node public-key pin and signing identity. A reader of this guide, a typewriter, writerly prose, reading scope, and fingerprints.</p>')
        output = render(source)
        self.assertEqual(annotated(output), [
            ('access-token', 'reader token'), ('access-token', 'writer bearer'),
            ('client-credentials', 'writer secret'), ('policy-writer', 'writer client'),
            ('write-outcome', 'write_outcome'), ('node-public-key-pin', 'Node public-key pin'),
            ('signing-identity', 'signing identity')])

    def test_links_interactive_and_aria_conflicts_are_untouched(self):
        source = document('<nav>Setup record</nav><p><a href="#x">reader token</a> <button>Setup record</button> <span role="button">Keychain item</span> <span aria-label="custom">Setup record</span> <span tabindex="0">Setup record</span> <span hidden>Setup record</span> <span contenteditable>Setup record</span></p><details><summary>Setup record</summary><p>Setup record</p></details><script>"Setup record"</script><style>/* Setup record */</style>')
        output = render(source)
        self.assertEqual(annotated(output), [('setup-record', 'Setup record')])
        self.assertEqual(atlas.clean(output), source)

    def test_svg_wrapped_text_tspans_entities_and_geometry(self):
        source = document('<div class="canvas" tabindex="0" role="region" aria-label="scroll"><svg role="img" viewBox="0 0 100 100" aria-labelledby="title"><title id="title">reader token</title><desc>Setup record</desc><text x="10" y="20" text-anchor="middle">Reader</text><text x="10" y="38" text-anchor="middle">token</text><text x="10" y="60"><tspan x="10">Node public-key</tspan><tspan x="10" dy="18">pin</tspan></text><text x="20" y="85">OAuth &amp; writer client</text><g aria-label="actor"><text x="1" y="1">Setup record</text></g></svg></div>')
        output = render(source)
        self.assertEqual(annotated(output), [('access-token', 'Reader'), ('access-token', 'token'), ('node-public-key-pin', 'Node public-key'), ('node-public-key-pin', 'pin'), ('policy-writer', 'writer client')])
        self.assertEqual(atlas.clean(output), source)
        self.assertEqual(render(output), output)

    def test_different_svg_objects_do_not_form_a_phrase(self):
        source = document('<svg><text x="1" y="1">Node public-key</text><text x="90" y="20">pin</text></svg>')
        self.assertEqual(annotated(render(source)), [])

    def test_cross_inline_phrase_without_link_bridging(self):
        source = document('<p>Node <em>public-key</em> pin. Reader <a href="#x">token</a>.</p>')
        self.assertEqual(annotated(render(source)), [('node-public-key-pin', 'Node '), ('node-public-key-pin', 'public-key'), ('node-public-key-pin', ' pin')])

    def test_escaped_dictionary_glossary_and_no_input_html(self):
        terms = '**Danger term**: A literal </script><script>alert("x")</script> & <img src=x>. Second sentence.'
        output = render(document('<p>Danger term &amp; unknown jargon.</p>'), terms)
        data = re.search(r'<script type="application/json" id="atlas-dictionary">(.*?)</script>', output, re.S).group(1)
        self.assertIn('</script>', json.loads(data)['danger-term']['definition'])
        self.assertNotIn('</script>', data)
        self.assertNotIn('<img src=x>', output)
        self.assertIn('&lt;img src=x&gt;', output)
        self.assertNotIn('innerHTML', JS)
        self.assertNotIn('fetch(', JS)
        self.assertIn('Field-guide vocabulary', output)
        self.assertIn('@media print', output)

    def test_idempotence_vocabulary_updates_and_self_loop_exclusion(self):
        source = document('<p>Setup record and Keychain item.</p>')
        first = render(source)
        self.assertEqual(render(first), first)
        changed = render(first, '**Setup record**: A revised definition with Keychain item in it.')
        self.assertEqual(annotated(changed), [('setup-record', 'Setup record')])
        self.assertEqual(atlas.clean(changed), source)
        self.assertEqual(changed.count(atlas.START), 1)
        self.assertIn('A revised definition', changed)

    def test_sentinel_corruption_is_not_overwritten(self):
        for broken in (atlas.START, atlas.END, atlas.END + atlas.START, atlas.START * 2 + atlas.END * 2):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                render(document(broken))

    def test_unknown_terms_do_not_prevent_generation(self):
        source = document('<p>Unknown jargon.</p>')
        output = render(source, '**New future term**: A canonical definition.')
        self.assertEqual(annotated(output), [])
        self.assertIn('New future term', output)
        self.assertEqual(atlas.clean(output), source)

    def test_real_atlas_round_trip_without_writing_it(self):
        source = (ROOT / 'Docs/trust-atlas.html').read_text()
        base = atlas.clean(source)
        output = render(base)
        self.assertEqual(atlas.clean(output), base)
        self.assertEqual(render(output), output)
        self.assertGreater(len(annotated(output)), 30)
        self.assertIn(('write-outcome', 'write_outcome'), annotated(output))

    def test_specific_phrases_do_not_fall_back_to_wrong_shorter_terms(self):
        source = document('<p>OAuth reader token; writer token; writer secret; reader client.</p>')
        output = render(source, '**Read-only client**: Reads policy.\n**Policy writer**: Writes policy.')
        self.assertEqual(annotated(output), [('read-only-client', 'reader client')])
        # A real canonical phrase wins over a generic inferred alias.
        output = render(source, TERMS + '\n**Reader token**: A specifically defined token.')
        self.assertIn(('reader-token', 'reader token'), annotated(output))

    def test_common_words_require_context_even_in_svg(self):
        source = document('<p>Reading scope. A reader of the guide. Biometric fingerprint. A Touch ID fingerprint. A fingerprint image. A project scope.</p><svg><text x="1" y="1">Reading scope</text><text x="1" y="40">Biometric fingerprint</text><text x="1" y="80">OAuth scope R</text><text x="1" y="120">Fingerprint = SHA-256(review.text)</text><text x="1" y="160">OAuth token issuer</text></svg>')
        self.assertEqual(annotated(render(source)), [('scope', 'scope'), ('review-fingerprint', 'Fingerprint')])

    def test_current_canonical_slugs_and_actual_atlas_in_memory(self):
        context = ROOT / 'CONTEXT.md'
        if not context.exists():
            self.skipTest('integration CONTEXT.md not yet supplied')
        markdown = context.read_text()
        source = atlas.clean((ROOT / 'Docs/trust-atlas.html').read_text())
        output, terms, used = atlas.generate(source, markdown, CSS, JS)
        self.assertIn('vm-node-public-key-pin', terms)
        self.assertIn('vm-node-public-key-pin', used)
        self.assertEqual(atlas.clean(output), source)
        self.assertEqual(render(output, markdown), output)
        sample = document('<p>VM node public-key pin; independently pinned node key; approval public-key pin; OAuth client secrets; configuration item; compiled candidate; plan signature; VM enrollment; read-only enrollment check; write_outcome.</p>')
        hits = annotated(render(sample, markdown))
        self.assertEqual([key for key, _ in hits[:9]], [
            'vm-node-public-key-pin', 'vm-node-public-key-pin', 'approval-public-key-pin',
            'client-credentials', 'setup-record', 'candidate-policy', 'approval-signature',
            'browser-enrollment', 'enrollment-check'])
        # No Write outcome definition yet: never turn it into a writer tip.
        self.assertNotIn(('policy-writer', 'write'), hits)

    @unittest.skipUnless(shutil.which('node'), 'Node unavailable for JS behavior check')
    def test_js_keyboard_svg_toggle_escape_outside_and_clamping(self):
        # A minimal event/DOM model, NOT a browser render or accessibility pass.
        harness = r'''
const assert = require('node:assert/strict');
class Element {
  constructor() { this.attrs = {}; this.listeners = {}; this.style = {}; this.dataset = {}; this.children = []; }
  setAttribute(k, v) { this.attrs[k] = v; }
  getAttribute(k) { return this.attrs[k]; }
  removeAttribute(k) { delete this.attrs[k]; }
  append(...nodes) { this.children.push(...nodes); }
  addEventListener(k, cb) { this.listeners[k] = cb; }
  contains(n) { return n === this || this.children.includes(n); }
  matches() { return false; }
  getBoundingClientRect() { return {left: 290, top: 210, bottom: 230, width: 280, height: 120}; }
}
const svg = new Element(); svg.setAttribute('role', 'img');
const trigger = new Element(); trigger.dataset.term = 'access-token';
trigger.closest = () => svg; // Deliberately NO .click(): this models SVGElement.
const dictionary = new Element();
dictionary.textContent = JSON.stringify({'access-token': {term: 'Access token', definition: '<literal definition>'}});
const body = new Element();
const document = {
  body, activeElement: null,
  documentElement: {clientWidth: 320, clientHeight: 240, classList: {add() {}}},
  getElementById: id => id === 'atlas-dictionary' ? dictionary : null,
  querySelectorAll: () => [trigger], createElement: () => new Element(),
  listeners: {}, addEventListener(k, cb) { this.listeners[k] = cb; }
};
const window = {addEventListener() {}};
'''
        assertions = r'''
const popup = body.children[0];
assert.equal(svg.getAttribute('role'), 'group');
assert.equal(trigger.getAttribute('tabindex'), '0');
let prevented = 0;
trigger.listeners.keydown({key: 'Enter', preventDefault() { prevented++; }});
assert.equal(popup.hidden, false);
assert.equal(popup.children[1].textContent, '<literal definition>');
assert.equal(trigger.getAttribute('aria-describedby'), 'atlas-term-popup');
assert.ok(parseFloat(popup.style.left) >= 12);
assert.ok(parseFloat(popup.style.left) + 280 <= 308);
assert.ok(parseFloat(popup.style.top) + 120 <= 228);
trigger.listeners.keydown({key: ' ', preventDefault() { prevented++; }});
assert.equal(popup.hidden, true);
trigger.listeners.focus();
document.listeners.keydown({key: 'Escape', preventDefault() { prevented++; }});
assert.equal(popup.hidden, true);
trigger.listeners.click();
document.listeners.pointerdown({target: new Element()});
assert.equal(popup.hidden, true);
assert.equal(prevented, 3);
'''
        result = subprocess.run(['node', '-'], input=harness + '\n' + JS + '\n' + assertions,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_check_generation_and_missing_input_are_nondestructive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative in ('Scripts/atlas-vocabulary.py', 'Docs/atlas-terms-ui.css', 'Docs/atlas-terms-ui.js'):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            target = root / 'Docs/trust-atlas.html'
            original = document('<p>Setup record</p>')
            target.write_text(original)
            command = ['python3', str(root / 'Scripts/atlas-vocabulary.py')]
            missing = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(missing.returncode, 2)
            self.assertIn('no HTML written', missing.stderr)
            self.assertEqual(target.read_text(), original)
            (root / 'CONTEXT.md').write_text(TERMS)
            check = subprocess.run(command + ['--check'], capture_output=True, text=True)
            self.assertEqual(check.returncode, 1, check.stderr)
            self.assertEqual(target.read_text(), original)
            generated = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            first = target.read_bytes()
            checked = subprocess.run(command + ['--check'], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(target.read_bytes(), first)


if __name__ == '__main__':
    unittest.main()
