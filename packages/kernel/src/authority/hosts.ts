// A HOST IS COMPARED IN ONE SPELLING. The registry of local hosts (`control-plane/workspace/local-targets.md`) says `localhost`, `127.0.0.1`
// and `::1`, and a host is compared to it WHOLE - a substring test is how `prod-localhost.acme.com` once read as the machine itself. Whole
// has a cost: an address has more than one spelling and a name has one more than it looks. `[0:0:0:0:0:0:0:1]` and `[::1]` are one address,
// `::ffff:127.0.0.1` is the IPv4 loopback in an IPv6 socket, `localhost.` is `localhost` with its root label written, `LOCALHOST` is
// `localhost` (wave 5, K8-06: each was EXTERNAL, so a Docker Desktop or kind cluster whose kubeconfig spells its server any of those ways
// was refused absolutely). The comparison is made once, in the spelling this module gives, by the one function that cuts a host out of an
// endpoint (`endpointHost` in the evaluator).
//
// WHAT IS NOT HERE: the other spellings of an IPv4 address (`127.1`, `0x7f.1`, `2130706433`). Resolvers disagree about those - Go's does not
// take them for addresses at all, libc's does - so no reading of them can be called right, and they stay what they were: external.

/** The eight 16-bit groups of an IPv6 literal, or null when the text is not one. An embedded IPv4 tail (`::ffff:1.2.3.4`) is its two groups. */
function ipv6Groups(text: string): number[] | null {
  if (!/^[0-9a-f:.]+$/.test(text)) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const side = (part: string): number[] | null => {
    if (part === '') return [];
    const out: number[] = [];
    const words = part.split(':');
    for (const [i, w] of words.entries()) {
      const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(w);
      if (v4 && i === words.length - 1) {
        const o = v4.slice(1).map(Number);
        if (o.some((x) => x > 255)) return null;
        out.push((o[0]! << 8) | o[1]!, (o[2]! << 8) | o[3]!);
      } else if (/^[0-9a-f]{1,4}$/.test(w)) out.push(parseInt(w, 16));
      else return null;
    }
    return out;
  };
  const head = side(halves[0]!);
  const tail = halves.length === 2 ? side(halves[1]!) : [];
  if (head === null || tail === null) return null;
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return null;
  return [...head, ...new Array<number>(halves.length === 2 ? fill : 0).fill(0), ...tail];
}

/** The one spelling of a host: lower case, no root label, an IPv6 address in its shortest form and an IPv4-mapped one as the IPv4 address. */
export function canonicalHost(raw: string): string {
  let h = raw.toLowerCase();
  if (h.length > 1 && h.endsWith('.') && !h.endsWith('..')) h = h.slice(0, -1);
  if (!h.includes(':')) return h;
  const g = ipv6Groups(h);
  if (g === null) return h;
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return `${g[6]! >> 8}.${g[6]! & 255}.${g[7]! >> 8}.${g[7]! & 255}`;
  // the longest run of zero groups, if it is at least two, is written `::`
  let best = { at: -1, len: 0 };
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > best.len) best = { at: i, len: j - i };
    i = j;
  }
  const hex = (xs: number[]): string => xs.map((x) => x.toString(16)).join(':');
  return best.len >= 2 ? `${hex(g.slice(0, best.at))}::${hex(g.slice(best.at + best.len))}` : hex(g);
}
