// WHERE A COPY OUT OF A CONTAINER OR A POD LANDS ON THIS MACHINE.
//
// `docker cp app:/x control-plane/permissions/matchers.md` writes a file whose content a container supplied into the policy that decides
// every later verdict, and `kubectl cp pod:/x .mcp.json` does the same to the agent's own configuration (wave 5, CT-08). The path
// scan knew `cp` as a writer by the NAME of the head, and `docker cp` and `kubectl cp` are not named `cp`: the destination was an
// operand like any other, a read, and no path rule was asked whether it may be written.
//
// ONE FUNCTION OF THE WORDS OF THE COMMAND. It places the verb with the container reader (containers.ts) or the cluster reader
// (k8s.ts), so a global option, a management group, a namespace-qualified pod or an option of the verb cannot move the operands, and
// it answers the one question: which operands are local files the copy WRITES. The evaluator judges each exactly as it judges the
// destination of `cp`: a write to a governed path is a write to a governed path, whoever supplied the bytes.
import { copyOperands, readContainerCommand } from './containers.ts';
import { k8sCopyOperands, type K8sWord } from './k8s.ts';

/** Whether a file spec names something INSIDE a container: `docker cp` takes `CONTAINER:PATH` where the part before the colon is a name
 *  (a path separator in it makes the whole word a local path that happens to hold a colon); `kubectl cp` takes `[NAMESPACE/]POD:PATH`,
 *  and any colon after the first character makes it one. */
const inside = (spec: string, tool: 'container' | 'cluster'): boolean => {
  const at = spec.indexOf(':');
  return at > 0 && (tool === 'cluster' || !spec.slice(0, at).includes('/'));
};

/** The local files a copy out of a container or a pod writes, as the words that name them (`-` is standard output and is not one).
 *  A copy IN reads the local side, which the path scan already judges as a read. */
export function copyOutDestinations(tokens: readonly string[]): string[] {
  const head = (tokens.find((t) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) ?? '').replace(/^.*\//, '');
  let specs: string[] | null = null;
  let tool: 'container' | 'cluster' = 'container';
  if (head === 'kubectl' || head === 'oc') {
    tool = 'cluster';
    const words: K8sWord[] = tokens
      .slice(tokens.findIndex((t) => t.replace(/^.*\//, '') === head) + 1)
      .map((text) => ({ text, quoted: false, expands: /[$`]/.test(text) }));
    specs = k8sCopyOperands(head, words);
  } else {
    const cc = readContainerCommand(tokens);
    if (cc !== null) specs = copyOperands(cc);
  }
  if (specs === null || specs.length < 2 || !inside(specs[0]!, tool)) return [];
  return specs.slice(1).filter((w) => w !== '-' && !inside(w, tool));
}
