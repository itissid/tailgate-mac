#!/usr/bin/env python3
"""Offline, source-preserving vocabulary layer for Docs/trust-atlas.html.

Canonical input: root CONTEXT.md entries of the form **Term**: definition.
Only definitions present in that file are used. Add specific aliases below, not
broad guesses (a client, its credential and its token are different objects).
Generated wrappers are reversible; the bundle lives between START and END.
No dependencies, network, HTML reserialization, or SVG coordinate changes.
"""
import argparse
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
START = '<!-- atlas-vocabulary:start -->'
END = '<!-- atlas-vocabulary:end -->'

# Keys are canonical slugs. Ambiguous aliases require allow_alias() below.
ALIASES = {
    'save-in-keychain': ['Save to Keychain'],
    'setup-record': ['configuration item', 'configuration record', 'setup item', 'local setup', 'configuration'],
    'keychain-item': ['Keychain items'],
    'create-only': ['create only'],
    'read-only-client': ['reader', 'reader client', 'read-only OAuth client', 'policy reader'],
    'policy-writer': ['writer', 'writer client', 'policy-write client'],
    'lookup-client': ['lookup-only client', 'lookup client'],
    'client-credentials': ['OAuth credentials', 'OAuth client credentials', 'client secret',
                           'client secrets', 'reader credential', 'writer credential',
                           'reader credentials', 'writer credentials', 'writer secret'],
    'access-token': ['OAuth token', 'OAuth bearer token', 'bearer token', 'reader token',
                     'writer token', 'reader-token', 'writer-token', 'reader bearer',
                     'writer bearer', 'policy-read bearer', 'inventory bearer'],
    'local-trust-check': ['local trust/configuration', 'local trust checks'],
    'keychain-access-group': ['private Keychain group', 'private access group', 'access group'],
    'review-plan': ['immutable review', 'frozen review', 'reviewed plan'],
    'review-fingerprint': ['fingerprint', 'review fingerprint'],
    'approval-signature': ['plan signature', 'biometric signature', 'exact-plan local signature'],
    'signing-identity': ['code identity', 'app identity', 'code-signing identity'],
    'node-public-key-pin': ['node public-key pin', 'node key', 'pinned node key',
                            'independently pinned node key'],
    'write-outcome': ['write_outcome', 'write outcome', 'write outcomes'],
    # Slugs below follow root CONTEXT.md, not names inferred from this page.
    'vm-node-public-key-pin': ['node public-key pin', 'node-key pin', 'VM node-key pin',
                              'node key', 'pinned node key', 'independently pinned node key',
                              'VM pin', 'pinned VM/node/tag'],
    'data-protection-keychain': ['Keychain'],
    'candidate-policy': ['compiled candidate', 'reviewed candidate', 'frozen candidate',
                         'exact validated candidate', 'candidate bytes', 'candidate'],
    'policy-validation': ['validation result'],
    'approval-key': ['approval private key', 'biometric signing key', 'biometric private key',
                     'Non-exportable P-256 key'],
    'approval-public-key-pin': ['pinned Secure Enclave public key', 'enclave approval pin',
                                'public pin', 'locally pinned public key'],
    'provisioning-profile': ['profile'],
    'conditional-policy-write': ['conditional POST', 'conditional policy POST', 'POST If-Match'],
    'intent-journal': ['Keychain journal', 'Keychain intent', 'durable write intent',
                       'JournalIntent', 'journal'],
    'write-history': ['applied history', 'immutable request/outcome history'],
    'unresolved-write': ['unresolved intent', 'unresolved intents', 'unfinished write'],
    'operator-receipt': ['saved receipt', 'initial receipt', 'confirmed receipt', 'mutable receipt'],
    'cli-receipt': ['sanitized receipt', 'stdout receipt', 'redacted JSON stdout receipt',
                    'bounded stdout receipt', 'limited status'],
    'read-only-reconciliation': ['read-only reconcile', 'reconcile read-only', 'reconciliation'],
    'device-lookup': ['device lookup', 'lookup'],
    'browser-enrollment': ['VM enrollment', 'human browser enrollment', 'Tailscale browser flow'],
    'enrollment-check': ['read-only enrollment check', 'read-only check'],
}
ALIASES['client-credentials'] += ['credentials', 'OAuth client secrets', 'OAuth credential',
                                  'reader/writer credentials']
ALIASES['access-token'] += ['OAuth access token', 'scoped bearer', 'fresh token', 'valid token',
                            'token', 'tokens', 'bearer']
ALIASES['review-plan'] += ['ReviewPlan', 'signed plan', 'exact signed review', 'signed review',
                           'exact review', 'reviewed request', 'plan']
ALIASES['signing-identity'] += ['release-signing key', 'release signer']
ALIASES['review-fingerprint'] += ['SHA-256 fingerprint', 'ID/fingerprint']
ALIASES['approval-public-key-pin'] += ['public-key pin', 'pinned public key']
BLOCKS = set('p li dt dd h1 h2 h3 h4 h5 h6 td th figcaption caption div section article header footer main blockquote pre'.split())
SKIP = set('a button input select option textarea label summary nav footer script style noscript template title desc defs metadata head'.split())
VOID = set('area base br col embed hr img input link meta param source track wbr'.split())
INTERACTIVE_ROLES = set('button link checkbox radio switch tab menuitem textbox combobox slider spinbutton'.split())


def slug(value):
    return re.sub(r'[^a-z0-9]+', '-', value.casefold()).strip('-')


def plain_markdown(value):
    value = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', value)
    return re.sub(r'[*`]', '', value).strip()


def definitions(markdown):
    """First one/two sentences of each canonical entry, never interpreted as HTML."""
    entry = re.compile(r'^\s*(?:[-*+]\s+)?\*\*([^*\n]+?)\*\*\s*:\s*(.*)$')
    alternate = re.compile(r'^\s*(?:[-*+]\s+)?\*\*([^*\n]+?):\*\*\s*(.*)$')
    lines = markdown.splitlines()
    result = {}
    fenced = False
    for index, line in enumerate(lines):
        if line.lstrip().startswith(('```', '~~~')):
            fenced = not fenced
        if fenced:
            continue
        match = entry.match(line) or alternate.match(line)
        if not match:
            continue
        name, first = match.groups()
        parts = [first.strip()]
        for following in lines[index + 1:]:
            if not following.strip() or following.lstrip().startswith('_Avoid_:') or re.match(r'\s*(?:#|[-*+] |\d+[.)] |```|~~~)', following) or entry.match(following) or alternate.match(following):
                break
            parts.append(following.strip())
        text = plain_markdown(' '.join(parts))
        # Do not split initials, e.g., i.e., or decimal/version numbers.
        ends = list(re.finditer(r'[.!?](?:[”"’\)]*)(?=\s+[A-Z]|$)', text))
        if len(ends) >= 2:
            text = text[:ends[1].end()]
        key = slug(name)
        if not key or not text:
            continue
        value = {'term': name.strip(), 'definition': text}
        if key in result and result[key] != value:
            raise ValueError('conflicting canonical term: ' + name)
        result[key] = value
    if not result:
        raise ValueError('CONTEXT.md has no canonical **Term**: definitions')
    return result


class Source(HTMLParser):
    """Track original offsets; never serialize the existing document."""
    def __init__(self, source):
        super().__init__(convert_charrefs=False)
        self.source = source
        self.lines = [0] + [m.end() for m in re.finditer('\n', source)]
        self.stack = []
        self.nodes = []
        self.unwrap = []
        self.counter = 0
        self.feed(source)
        self.close()

    def source_offset(self):
        line, column = self.getpos()
        return self.lines[line - 1] + column

    def handle_starttag(self, tag, attrs):
        start = self.source_offset()
        end = start + len(self.get_starttag_text())
        attrs = dict(attrs)
        self.counter += 1
        own = tag in ('span', 'tspan') and attrs.get('data-atlas-term') == '1'
        if own:
            self.unwrap.append((start, end, ''))
        inherited = bool(self.stack and self.stack[-1]['skip'])
        role = attrs.get('role', '').lower()
        chrome = bool(set(attrs.get('class', '').split()) & {'topline', 'indexnum', 'kicker', 'nav', 'refs', 'legend'})
        conflict = (chrome or role in INTERACTIVE_ROLES or 'contenteditable' in attrs or
                    'aria-hidden' in attrs or 'hidden' in attrs or
                    'data-term' in attrs or
                    ('aria-label' in attrs and tag not in ('svg', 'figure', 'div')) or
                    ('tabindex' in attrs and tag not in ('svg', 'div')))
        item = {'tag': tag, 'attrs': attrs, 'id': self.counter,
                'skip': inherited or tag in SKIP or conflict,
                'own': own}
        if tag not in VOID:
            self.stack.append(item)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.stack.pop()

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]['tag'] == tag:
                if self.stack[index]['own']:
                    start = self.source_offset()
                    self.unwrap.append((start, self.source.index('>', start) + 1, ''))
                del self.stack[index:]
                return

    def handle_data(self, data):
        self.text(data)

    def handle_entityref(self, name):
        self.text('&' + name + ';')

    def handle_charref(self, name):
        self.text('&#' + name + ';')

    def text(self, raw):
        if not self.stack or self.stack[-1]['skip']:
            return
        if not any(n['tag'] in ('body', 'svg') for n in self.stack):
            return
        svg = next((n for n in reversed(self.stack) if n['tag'] == 'svg'), None)
        text = next((n for n in reversed(self.stack) if n['tag'] == 'text'), None)
        if svg and not text:
            return
        block = next((n['id'] for n in reversed(self.stack) if n['tag'] in BLOCKS), 0)
        node = {'start': self.source_offset(), 'raw': raw, 'block': block,
                'svg': svg['id'] if svg else None, 'text': text,
                'parent': self.stack[-1]['id']}
        if self.nodes and self.nodes[-1]['start'] + len(self.nodes[-1]['raw']) == node['start'] and self.nodes[-1]['parent'] == node['parent']:
            self.nodes[-1]['raw'] += raw
        else:
            self.nodes.append(node)


def replace(source, edits):
    for start, end, value in sorted(edits, reverse=True):
        source = source[:start] + value + source[end:]
    return source


def clean(source):
    if source.count(START) != source.count(END) or source.count(START) > 1:
        raise ValueError('unbalanced or duplicate atlas-vocabulary sentinels')
    if START in source:
        start, end = source.index(START), source.index(END)
        if end < start:
            raise ValueError('reversed atlas-vocabulary sentinels')
        source = source[:start] + source[end + len(END):]
    return replace(source, Source(source).unwrap)


def decoded(raw, start):
    chars, offsets = [], []
    for match in re.finditer(r'&(?:#[xX][0-9a-fA-F]+|#\d+|[A-Za-z][A-Za-z0-9]+);|.', raw, re.S):
        value = html.unescape(match.group())
        chars.append(value)
        offsets.extend([(start + match.start(), start + match.end())] * len(value))
    return ''.join(chars), offsets


def joined_svg(left, right):
    """Only consecutive aligned lines; do not join different diagram objects."""
    if left['svg'] != right['svg'] or not left['svg']:
        return False
    a, b = left['text'], right['text']
    if a['id'] == b['id']:
        return True
    aa, bb = a['attrs'], b['attrs']
    try:
        return (aa.get('x') == bb.get('x') and aa.get('text-anchor') == bb.get('text-anchor')
                and 0 < float(bb['y']) - float(aa['y']) <= 25)
    except (KeyError, ValueError):
        return False


def allow_alias(alias, text, match, svg):
    name = alias.casefold()
    before, after = text[:match.start()], text[match.end():]
    sentence = re.split(r'[.!?;\n]', before)[-1] + match.group() + re.split(r'[.!?;\n]', after)[0]
    window = text[max(0, match.start() - 100):match.end() + 100]
    if name.endswith('token') and re.match(r'\s+(?:issuer|service)\b', after, re.I):
        return False
    if name in ('public-key pin', 'pinned public key'):
        return (bool(re.search(r'\b(?:approval|signature|Secure Enclave|signing|biometric)\b', sentence, re.I))
                and not re.search(r'\b(?:node|VM|machine)\b', sentence, re.I))
    if name in ('reader', 'writer'):
        if re.search(r'\b(?:person|human|guide|prose|reading)\b', sentence, re.I):
            return False
        return bool(re.search(r'\b(?:client|credential|OAuth|policy|reader/writer|scope)\b', sentence, re.I))
    if name in ('scope', 'scopes'):
        if re.search(r'(?:reading|document|project|out.of)\s*$', before, re.I):
            return False
        return bool(re.search(r'\b(?:OAuth|token|writer|reader|policy_file|devices:)\b|\bscope\s+(?:R|I|W)\b', sentence, re.I))
    if name == 'fingerprint':
        if re.search(r'\b(?:biometric|finger|Touch ID)\s*$', before, re.I):
            return False
        return bool(re.search(r'\b(?:review|plan|SHA-256|pending)\b', sentence, re.I))
    if name == 'configuration':
        return (bool(re.search(r'\b(?:protected|Keychain|setup|loads|existing)\b', sentence, re.I))
                and not re.match(r'\s+stamp\b', after, re.I))
    if name in ('credentials', 'credential'):
        return bool(re.search(r'\b(?:OAuth|client|setup|stored|loads|releasing|protected|agent|signing key)\b', sentence, re.I))
    if name in ('token', 'tokens', 'bearer'):
        # Routes and token-service components are not an access token object.
        if before.endswith('/') or re.match(r'\s*(?:issuer|service|acquisition)\b', after, re.I):
            return False
        return svg or bool(re.search(r'\b(?:OAuth|Tailscale|API|bearer|scope|fresh|cache|stolen|writer|reader|VM|agent)\b', sentence, re.I))
    if name == 'keychain':
        return not re.search(r'\b(?:file-based|lab|experiment|dummy)\b', window, re.I)
    if name == 'profile':
        return svg or bool(re.search(r'\b(?:Apple|provisioning|app ID|identity|Keychain|private group)\b', sentence, re.I))
    if name in ('plan', 'plans'):
        return svg or bool(re.search(r'\b(?:review|signature|UUID|expiry|candidate|approval|policy|deadline|signed)\b', sentence, re.I))
    if name in ('candidate', 'candidates'):
        return svg or bool(re.search(r'\b(?:policy|compiled|diff|review|bytes|ETag|validation|Tailgate|app)\b', sentence, re.I))
    if name in ('lookup', 'lookups'):
        return svg or bool(re.search(r'\b(?:device|hostname|disclosure|write|Pi)\b', sentence, re.I))
    if name in ('tag', 'tags'):
        return svg or bool(re.search(r'\b(?:device|policy|approved|holder|occupied|assignment|retagging|inventory|Tailgate|Pi)\b', sentence, re.I))
    return True


def annotate(source, terms):
    aliases = {}
    canonical = {}
    def plural(name):
        if name.endswith('y') and not name.endswith(('ay', 'ey', 'oy')):
            return name[:-1] + 'ies'
        return name + 's' if not name.endswith('s') else name
    for key, value in terms.items():
        canonical[value['term'].casefold()] = key
        names = [value['term'], plural(value['term'])] + ALIASES.get(key, [])
        for alias in names:
            aliases.setdefault(alias.casefold(), set()).add(key)
    # Explicit canonical names take priority; conflicting inferred aliases do not.
    aliases = {name: canonical.get(name, next(iter(keys)) if len(keys) == 1 else None)
               for name, keys in aliases.items()}
    # Reserve specific phrases even when their definition hasn't landed, so a
    # missing Access token never turns 'reader token' into a reader-client tip.
    for names in ALIASES.values():
        for name in names:
            if ' ' in name or '-' in name:
                aliases.setdefault(name.casefold(), None)
    expression = '|'.join(re.escape(a).replace(r'\ ', r'\s+').replace(r'\-', '[-–‑]')
                          for a in sorted(aliases, key=lambda a: (-len(a), a)))
    pattern = re.compile(r'(?<![\w/.-])(?:' + expression + r')(?![\w/-])', re.I)
    nodes = Source(source).nodes
    groups = []
    for node in nodes:
        if groups:
            last = groups[-1][-1]
            gap = source[last['start'] + len(last['raw']):node['start']]
            # Excluded content forms a hard boundary, including link text.
            safe_inline = not re.sub(r'</?(?:em|strong|b|i|code|span|small|sup|sub)(?:\s[^>]*)?>', '', gap).strip()
            together = joined_svg(last, node) if node['svg'] or last['svg'] else (last['block'] == node['block'] and safe_inline)
        else:
            together = False
        if together:
            groups[-1].append(node)
        else:
            groups.append([node])
    edits, used = [], set()
    for group in groups:
        text, mapping = '', []
        for node in group:
            value, offsets = decoded(node['raw'], node['start'])
            if group[0]['svg'] and text and value and not text[-1].isspace() and not value[0].isspace():
                text += ' '
                mapping.append(None)
            text += value
            mapping.extend((node, a, b) for a, b in offsets)
        for match in pattern.finditer(text):
            alias = re.sub(r'\s+', ' ', match.group()).casefold().replace('–', '-').replace('‑', '-')
            key = aliases.get(alias)
            if not key or not allow_alias(alias, text, match, bool(group[0]['svg'])):
                continue
            slices = []
            for location in mapping[match.start():match.end()]:
                if location is None:
                    continue
                node, a, b = location
                if slices and slices[-1][0] is node and slices[-1][2] >= a:
                    slices[-1] = (node, slices[-1][1], max(b, slices[-1][2]))
                else:
                    slices.append((node, a, b))
            for node, start, end in slices:
                tag = 'tspan' if node['svg'] else 'span'
                title = html.escape(terms[key]['term'] + ': ' + terms[key]['definition'], quote=True)
                opening = f'<{tag} data-atlas-term="1" data-term="{key}" title="{title}">'
                edits.append((start, end, opening + source[start:end] + f'</{tag}>'))
            used.add(key)
    return replace(source, edits), used


def bundle(terms, css, js):
    dictionary = json.dumps(terms, ensure_ascii=False, sort_keys=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    glossary = ''.join('<dt id="atlas-definition-' + key + '">' + html.escape(value['term']) + '</dt><dd>' + html.escape(value['definition']) + '</dd>' for key, value in sorted(terms.items(), key=lambda item: item[1]['term'].casefold()))
    return (START + '\n<style>\n' + css.rstrip() + '\n</style>\n'
            '<section id="atlas-glossary" class="atlas-glossary" aria-labelledby="atlas-glossary-title">'
            '<h2 id="atlas-glossary-title">Field-guide vocabulary</h2>'
            '<p>Definitions from <code>CONTEXT.md</code>. Underlined terms show these definitions; '
            'this glossary also works without JavaScript and in print.</p><dl>' + glossary + '</dl></section>\n'
            '<script type="application/json" id="atlas-dictionary">' + dictionary + '</script>\n'
            '<script>\n' + js.rstrip() + '\n</script>\n' + END)


def generate(source, markdown, css, js):
    terms = definitions(markdown)
    base = clean(source)
    if len(re.findall(r'</body\s*>', base, re.I)) != 1:
        raise ValueError('expected one closing </body> in atlas HTML')
    marked, used = annotate(base, terms)
    insertion = re.search(r'</body\s*>', marked, re.I).start()
    output = marked[:insertion] + bundle(terms, css, js) + marked[insertion:]
    return output, terms, used


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='do not write; exit 1 if regeneration would change HTML')
    args = parser.parse_args(argv)
    target = ROOT / 'Docs/trust-atlas.html'
    try:
        source = target.read_text(encoding='utf-8')
        output, terms, used = generate(source, (ROOT / 'CONTEXT.md').read_text(encoding='utf-8'),
                                      (ROOT / 'Docs/atlas-terms-ui.css').read_text(encoding='utf-8'),
                                      (ROOT / 'Docs/atlas-terms-ui.js').read_text(encoding='utf-8'))
        if output != source:
            if args.check:
                print('atlas vocabulary is stale; run python3 Scripts/atlas-vocabulary.py', file=sys.stderr)
                return 1
            target.write_text(output, encoding='utf-8')
        print(f'atlas vocabulary: {len(terms)} definitions, {len(used)} used; ' + ('current' if args.check else 'generated'))
        unused = sorted(set(terms) - used)
        if unused:
            print('note: no safe visible match for: ' + ', '.join(unused), file=sys.stderr)
        return 0
    except (OSError, ValueError) as error:
        print('atlas vocabulary: ' + str(error) + '; no HTML written', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
