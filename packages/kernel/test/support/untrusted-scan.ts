// THE STRUCTURAL GUARD OF CHANNEL INTEGRITY (closure audit 2026-10-02, AUTH-6). Text that is not EGO's - a layer file's, a repository's, a
// host's - is DECLARED where it enters the program: a property or a function whose documentation carries `@untrusted`. This scan reads every
// source file under packages/*/src with the type checker and finds each place that builds a string (a template literal, a `+`) out of an
// expression that carries a declared source, and requires the expression to pass through `shownText`, `shownList`, `shownToken`, `flatText`
// or `terminalSafe` first. The sources are found by DECLARATION, not listed here: a new loader of foreign text declares its fields, and the
// scan finds every place that prints them.
//
// WHAT CARRIES FOREIGN TEXT: a property access whose symbol is declared `@untrusted`; a call of a function so declared; a METHOD called on
// something that carries (`d.name.slice(0, 3)`, `lines.join()`); an expression made of one (`a ?? b`, a ternary); a variable initialised from
// one (to a depth of four); the parameter of a callback handed to a method of an expression that carries (`ignored.map((i) => ...)`); a
// `for ... of` variable over one. Only string-typed expressions carry: a count, a boolean or an index derived from a tainted lookup is not
// text. A plain function called WITH a tainted argument does not carry (its result is whatever it computes); the arguments are the
// callee's to handle, and the boundary (`terminalSafe` on every write, tested separately) is the net under it.
//
// WHAT IT DOES NOT FOLLOW is data flow across a function boundary (a string passed as an argument and built into a message inside the callee).
// A function whose body is a bare call of a wrapper (`const shown = (m) => shownText(...)`) is a wrapper itself.
//
// WHAT IT SKIPS, because it is not a message: the `key` of an object (a producer's identity), and the functions in `INTERNAL`, which build a
// string used only as a lookup key and never shown.
import { readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import ts from 'typescript';

export interface Violation {
  /** `file:line` */
  where: string;
  /** the function the construct is in */
  inside: string;
  /** the string-building expression, shortened */
  text: string;
}

/** the functions that turn foreign text into data safe to embed in a sentence */
const WRAPPERS = new Set(['shownText', 'shownList', 'shownToken', 'flatText', 'terminalSafe']);
/** functions that build a string used only as a key, never shown (each says why) */
export const INTERNAL: Readonly<Record<string, string>> = {
  matcherPattern: 'the identity of a rule, compared and never printed',
  guardedPath: 'the place an overlay path rule guards, compared against the roots a search reaches',
};

export function scanUntrusted(repoRoot: string): { violations: Violation[]; sources: string[] } {
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const e of readdirSync(dir)) {
      const p = join(dir, e);
      if (statSync(p).isDirectory()) {
        if (e !== 'node_modules') walk(p);
      } else if (p.endsWith('.ts') && /packages\/[^/]+\/src\//.test(p)) files.push(p);
    }
  };
  walk(join(repoRoot, 'packages'));
  const base = ts.readConfigFile(join(repoRoot, 'tsconfig.base.json'), ts.sys.readFile).config as { compilerOptions: Record<string, unknown> };
  const { options } = ts.convertCompilerOptionsFromJson(base.compilerOptions, repoRoot);
  const program = ts.createProgram(files, { ...options, noEmit: true });
  const checker = program.getTypeChecker();
  const own = new Set(files);
  const sourceFiles = program.getSourceFiles().filter((sf) => own.has(sf.fileName));

  // ---- the declared sources, and the helpers that are wrappers
  const tagged = new Set<ts.Symbol>();
  const sources: string[] = [];
  const wrapperNames = new Set(WRAPPERS);
  const hasTag = (n: ts.Node): boolean => ts.getJSDocTags(n).some((t) => t.tagName.text === 'untrusted');
  const calleeName = (c: ts.CallExpression): string =>
    ts.isPropertyAccessExpression(c.expression) ? c.expression.name.text : ts.isIdentifier(c.expression) ? c.expression.text : '';
  for (const sf of sourceFiles) {
    const visit = (n: ts.Node): void => {
      if (
        (ts.isPropertySignature(n) || ts.isPropertyDeclaration(n) || ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n) || ts.isVariableDeclaration(n)) &&
        n.name &&
        hasTag(n)
      ) {
        const sym = checker.getSymbolAtLocation(n.name);
        if (sym) {
          tagged.add(sym);
          sources.push(`${relative(repoRoot, sf.fileName)}:${sym.getName()}`);
        }
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  // a helper whose whole body is a call of a wrapper is a wrapper (to a fixed point)
  for (let changed = true; changed; ) {
    changed = false;
    for (const sf of sourceFiles) {
      const visit = (n: ts.Node): void => {
        let name: string | null = null;
        let body: ts.Node | undefined;
        if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))) {
          name = n.name.text;
          body = n.initializer.body;
        } else if (ts.isFunctionDeclaration(n) && n.name) {
          name = n.name.text;
          body = n.body;
        }
        if (name && body && !wrapperNames.has(name)) {
          const expr = ts.isBlock(body) ? (body.statements.length === 1 && ts.isReturnStatement(body.statements[0]!) ? body.statements[0].expression : undefined) : body;
          if (expr && ts.isCallExpression(expr) && wrapperNames.has(calleeName(expr))) {
            wrapperNames.add(name);
            changed = true;
          }
        }
        ts.forEachChild(n, visit);
      };
      visit(sf);
    }
  }

  // ---- does an expression carry foreign text that has not been made safe
  const taintedSymbol = (node: ts.Node): boolean => {
    const sym = checker.getSymbolAtLocation(node);
    return sym !== undefined && tagged.has(sym);
  };
  const isText = (e: ts.Node): boolean => {
    const t = checker.getTypeAtLocation(e);
    const stringy = (x: ts.Type): boolean =>
      (x.flags & (ts.TypeFlags.StringLike | ts.TypeFlags.Any | ts.TypeFlags.Unknown | ts.TypeFlags.TemplateLiteral)) !== 0 ||
      (x.isUnion() && x.types.some(stringy)) ||
      (checker.isArrayType(x) && checker.getTypeArguments(x as ts.TypeReference).some(stringy));
    return stringy(t);
  };
  const carries = (e: ts.Node, depth: number): boolean => {
    if (!ts.isCallExpression(e) && !ts.isIdentifier(e) && !ts.isPropertyAccessExpression(e) && !ts.isElementAccessExpression(e) && !isTransparent(e) && !isText(e)) return false;
    if (ts.isCallExpression(e)) {
      if (wrapperNames.has(calleeName(e))) return false;
      if (taintedSymbol(ts.isPropertyAccessExpression(e.expression) ? e.expression.name : e.expression)) return true;
      if (ts.isPropertyAccessExpression(e.expression)) {
        // `xs.map((x) => <carrying>)`: the array holds what the callback returns
        const cb = e.arguments[0];
        if (e.expression.name.text === 'map' && cb && (ts.isArrowFunction(cb) || ts.isFunctionExpression(cb)) && !ts.isBlock(cb.body) && carries(cb.body, depth)) return true;
        // a method called on something that carries (slice, trim, join, toLowerCase, ...): the receiver is the text
        return isText(e) && carries(e.expression.expression, depth);
      }
      return false;
    }
    if (ts.isPropertyAccessExpression(e)) {
      if (taintedSymbol(e.name)) return isText(e);
      return isText(e) && carries(e.expression, depth);
    }
    // a conditional carries what its BRANCHES carry, not what its test reads; a template is judged where it stands (its spans are visited on their own)
    if (ts.isConditionalExpression(e)) return carries(e.whenTrue, depth) || carries(e.whenFalse, depth);
    if (ts.isTemplateExpression(e)) return false;
    if (ts.isBinaryExpression(e)) {
      const op = e.operatorToken.kind;
      if (op === ts.SyntaxKind.AmpersandAmpersandToken) return carries(e.right, depth);
      if (op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken || op === ts.SyntaxKind.PlusToken) return carries(e.left, depth) || carries(e.right, depth);
      return false;
    }
    if (ts.isIdentifier(e)) {
      if (depth <= 0 || !isText(e)) return false;
      if (taintedSymbol(e)) return true;
      const sym = checker.getSymbolAtLocation(e);
      for (const d of sym?.declarations ?? []) {
        if (ts.isVariableDeclaration(d)) {
          if (d.initializer && carries(d.initializer, depth - 1)) return true;
          // `for (const x of <carrying>)`
          const stmt = d.parent?.parent;
          if (stmt && ts.isForOfStatement(stmt) && carriesCollection(stmt.expression, depth - 1)) return true;
        }
        if (ts.isParameter(d)) {
          // a callback parameter: `<carrying>.map((x) => ...)`
          const fn = d.parent;
          const call = fn.parent;
          if ((ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && ts.isCallExpression(call) && ts.isPropertyAccessExpression(call.expression) && carriesCollection(call.expression.expression, depth - 1)) return true;
        }
      }
      return false;
    }
    return ts.forEachChild(e, (c) => (carries(c, depth) ? true : undefined)) ?? false;
  };
  /** a collection (an array of records, a list of strings) whose elements carry */
  const carriesCollection = (e: ts.Node, depth: number): boolean => {
    if (ts.isPropertyAccessExpression(e) && taintedSymbol(e.name)) return true;
    if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) return carriesCollection(e.expression, depth);
    if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression)) {
      const cb = e.arguments[0];
      if (e.expression.name.text === 'map' && cb && (ts.isArrowFunction(cb) || ts.isFunctionExpression(cb)) && !ts.isBlock(cb.body) && carries(cb.body, depth)) return true;
      return carriesCollection(e.expression.expression, depth);
    }
    if (ts.isIdentifier(e) && depth > 0) {
      if (taintedSymbol(e)) return true;
      return (checker.getSymbolAtLocation(e)?.declarations ?? []).some((d) => ts.isVariableDeclaration(d) && d.initializer !== undefined && carriesCollection(d.initializer, depth - 1));
    }
    return false;
  };
  function isTransparent(e: ts.Node): boolean {
    return ts.isParenthesizedExpression(e) || ts.isNonNullExpression(e) || ts.isAsExpression(e) || ts.isConditionalExpression(e) || ts.isBinaryExpression(e);
  }

  // ---- every place that builds a string
  const violations: Violation[] = [];
  for (const sf of sourceFiles) {
    const enclosing = (n: ts.Node): string => {
      for (let p: ts.Node | undefined = n.parent; p; p = p.parent) {
        if ((ts.isFunctionDeclaration(p) || ts.isMethodDeclaration(p)) && p.name) return p.name.getText(sf);
        if (ts.isVariableDeclaration(p) && p.initializer && (ts.isArrowFunction(p.initializer) || ts.isFunctionExpression(p.initializer))) return p.name.getText(sf);
      }
      return '(module)';
    };
    /** `key: \`...\`` is an identity, not a message */
    const isKey = (n: ts.Node): boolean => {
      for (let p: ts.Node | undefined = n.parent; p && !ts.isBlock(p); p = p.parent)
        if (ts.isPropertyAssignment(p)) return p.name.getText(sf) === 'key';
      return false;
    };
    const report = (n: ts.Node, piece: ts.Node): void => {
      if (isKey(n) || enclosing(n) in INTERNAL) return;
      const { line } = sf.getLineAndCharacterOfPosition(piece.getStart(sf));
      violations.push({ where: `${relative(repoRoot, sf.fileName)}:${line + 1}`, inside: enclosing(n), text: n.getText(sf).replace(/\s+/g, ' ').slice(0, 110) });
    };
    const visit = (n: ts.Node): void => {
      if (ts.isTemplateExpression(n)) {
        for (const span of n.templateSpans) if (carries(span.expression, 4)) report(n, span.expression);
      } else if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
        const stringy = (x: ts.Node): boolean => ts.isStringLiteralLike(x) || ts.isTemplateExpression(x) || checker.typeToString(checker.getTypeAtLocation(x)) === 'string';
        if (stringy(n.left) || stringy(n.right)) for (const side of [n.left, n.right]) if (!ts.isStringLiteralLike(side) && !ts.isBinaryExpression(side) && carries(side, 4)) report(n, side);
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return { violations, sources: sources.sort() };
}
