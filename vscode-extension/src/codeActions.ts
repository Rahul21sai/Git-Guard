import * as vscode from 'vscode';
import * as path from 'path';

/**
 * GitGuard — Code action provider
 * Offers quick-fix actions for flagged lines.
 */
export class GitGuardCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'GitGuard') continue;

      const meta = (diagnostic as any).gitguardMeta as {
        type: string;
        match: string;
        lineText: string;
      } | undefined;

      if (!meta) continue;

      // Action 1: Move to .env and replace with process.env
      const moveAction = this.buildMoveToEnvAction(document, diagnostic, meta);
      if (moveAction) actions.push(moveAction);

      // Action 2: Add to .gitguardignore
      actions.push(this.buildIgnoreAction(document, diagnostic, meta));
    }

    return actions;
  }

  // ---------------------------------------------------------------------------
  // Action 1 — Move value to .env and replace with process.env reference
  // ---------------------------------------------------------------------------
  private buildMoveToEnvAction(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    meta: { type: string; match: string; lineText: string }
  ): vscode.CodeAction | null {
    const varName = this.extractVarName(meta.lineText, meta.match);
    if (!varName) return null;

    const envKey = varName.toUpperCase().replace(/[^A-Z0-9]/g, '_');

    const action = new vscode.CodeAction(
      `GitGuard: Move to .env and replace with process.env.${envKey}`,
      vscode.CodeActionKind.QuickFix
    );
    action.diagnostics = [diagnostic];
    action.isPreferred  = true;
    action.command = {
      command: 'gitguard.moveToEnv',
      title:   'Move secret to .env',
      arguments: [document.uri, diagnostic.range, meta.match, envKey],
    };

    // Register the command handler inline if not already registered
    // (the extension activation registers all commands via this provider)
    this.ensureMoveToEnvCommand();

    return action;
  }

  private ensureMoveToEnvCommand(): void {
    // Commands are registered once in activate() — this is a no-op guard
    if ((this as any)._commandRegistered) return;
    (this as any)._commandRegistered = true;

    vscode.commands.registerCommand(
      'gitguard.moveToEnv',
      async (
        uri: vscode.Uri,
        range: vscode.Range,
        secretValue: string,
        envKey: string
      ) => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) return;

        const root = workspaceFolders[0].uri;

        // 1. Append to .env
        await appendToFile(vscode.Uri.joinPath(root, '.env'), `${envKey}=${secretValue}\n`);

        // 2. Append to .env.example (empty value)
        await appendToFile(vscode.Uri.joinPath(root, '.env.example'), `${envKey}=\n`);

        // 3. Add .env to .gitignore if missing
        await ensureGitignoreEntry(root, '.env');

        // 4. Replace value in the source file
        const edit = new vscode.WorkspaceEdit();
        edit.replace(uri, range, `process.env.${envKey}`);
        await vscode.workspace.applyEdit(edit);

        vscode.window.showInformationMessage(
          `GitGuard: Moved ${envKey} to .env and updated reference.`
        );
      }
    );
  }

  // ---------------------------------------------------------------------------
  // Action 2 — Add to .gitguardignore
  // ---------------------------------------------------------------------------
  private buildIgnoreAction(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    meta: { type: string; match: string; lineText: string }
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      'GitGuard: Add this line to .gitguardignore',
      vscode.CodeActionKind.QuickFix
    );
    action.diagnostics = [diagnostic];
    action.command = {
      command: 'gitguard.addToIgnore',
      title:   'Add to .gitguardignore',
      arguments: [meta.match],
    };

    this.ensureAddToIgnoreCommand();
    return action;
  }

  private ensureAddToIgnoreCommand(): void {
    if ((this as any)._ignoreCommandRegistered) return;
    (this as any)._ignoreCommandRegistered = true;

    vscode.commands.registerCommand(
      'gitguard.addToIgnore',
      async (pattern: string) => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) return;

        const root  = workspaceFolders[0].uri;
        const escaped = escapeRegExp(pattern);
        await appendToFile(vscode.Uri.joinPath(root, '.gitguardignore'), `${escaped}\n`);

        vscode.window.showInformationMessage('GitGuard: Pattern added to .gitguardignore');
      }
    );
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------
  private extractVarName(lineText: string, secretValue: string): string | null {
    // Match: varName = "value" | varName = 'value' | varName = value
    const re = /([a-zA-Z_][a-zA-Z0-9_]*)\s*[=:]\s*['"]?/g;
    let m;
    while ((m = re.exec(lineText)) !== null) {
      const afterVar = lineText.slice(m.index + m[0].length);
      if (afterVar.startsWith(secretValue)) {
        return m[1];
      }
    }
    return null;
  }
}

// ---------------------------------------------------------------------------
// File-system helpers
// ---------------------------------------------------------------------------
async function appendToFile(uri: vscode.Uri, content: string): Promise<void> {
  let existing = '';
  try {
    existing = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf8');
  } catch {
    // File doesn't exist — create it
  }
  if (!existing.endsWith('\n') && existing.length > 0) existing += '\n';
  const newContent = Buffer.from(existing + content, 'utf8');
  await vscode.workspace.fs.writeFile(uri, newContent);
}

async function ensureGitignoreEntry(root: vscode.Uri, entry: string): Promise<void> {
  const gitignoreUri = vscode.Uri.joinPath(root, '.gitignore');
  let content = '';
  try {
    content = Buffer.from(await vscode.workspace.fs.readFile(gitignoreUri)).toString('utf8');
  } catch { /* file doesn't exist */ }

  const lines = content.split('\n').map((l) => l.trim());
  if (!lines.includes(entry)) {
    await appendToFile(gitignoreUri, `${entry}\n`);
  }
}

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
