// Percent-decoding of text that comes from a command line, a URL or a file: a malformed escape is text, not an exception.
//
// `decodeURIComponent('%zz')` throws a URIError, and a presenter that let it out turned `gh api repos/octo/%zz/issues -X POST` -
// an ASK - into an exit 2 that no human could approve (closure audit 2026-10-02, AUTH-12). Input is hostile by default; a
// decoder that is called on it answers for every input.

/** `s` percent-decoded, or `s` as it is when it is not valid percent-encoding (a lone `%`, `%zz`, a truncated UTF-8 sequence). */
export function decodeUriComponentOrRaw(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
