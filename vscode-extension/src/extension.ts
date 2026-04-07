import * as vscode from 'vscode';
import { scanLine, parseGitguardignore, previewSecret } from './scanner';
import { GitGuardCodeActionProvider } from './codeActions';
import { StatusBarManager } from './statusBar';

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBar: StatusBarManager;
let debounceTimer: NodeJS.Timeout | undefined;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('gitguard');
  context.subscriptions.push(diagnosticCollection);

  statusBar = new StatusBarManager(context);

  // Register code action provider for all file types
  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    { scheme: 'file' },
    new GitGuardCodeActionProvider(),
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
  );
  context.subscriptions.push(codeActionProvider);

  // Scan the active document on activation
  if (vscode.window.activeTextEditor) {
    scanDocument(vscode.window.activeTextEditor.document);
  }

  // File open
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) scanDocument(editor.document);
    })
  );

  // File save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration('gitguard');
      if (config.get<boolean>('scanOnSave', true)) {
        scanDocument(doc);
      }
    })
  );

  // Text change — debounced
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        scanDocument(event.document);
      }, 800);
    })
  );

  // File close — clear diagnostics
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
    })
  );
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
  statusBar?.dispose();
}

// ---------------------------------------------------------------------------
// Core scan function
// ---------------------------------------------------------------------------
async function scanDocument(document: vscode.TextDocument): Promise<void> {
  const config = vscode.workspace.getConfiguration('gitguard');
  if (!config.get<boolean>('enable', true)) {
    diagnosticCollection.set(document.uri, []);
    statusBar.update(0);
    return;
  }

  // Skip non-file documents
  if (document.uri.scheme !== 'file') return;

  const allowlist = await loadWorkspaceAllowlist();
  const entropyThreshold = config.get<number>('entropyThreshold', 4.5);
  const opts = { allowlist, entropyThreshold };

  const diagnostics: vscode.Diagnostic[] = [];

  for (let i = 0; i < document.lineCount; i++) {
    const lineText = document.lineAt(i).text;
    const findings = scanLine(lineText, opts);

    for (const finding of findings) {
      const valueStart = lineText.indexOf(finding.match);
      if (valueStart === -1) continue;

      const range = new vscode.Range(
        new vscode.Position(i, valueStart),
        new vscode.Position(i, valueStart + finding.match.length)
      );

      const diag = new vscode.Diagnostic(
        range,
        `GitGuard: Possible ${finding.type} detected. Move to .env file.`,
        vscode.DiagnosticSeverity.Warning
      );
      diag.code     = `GITGUARD_${finding.type.toUpperCase().replace(/\s+/g, '_')}`;
      diag.source   = 'GitGuard';
      // Store metadata for code actions
      (diag as any).gitguardMeta = {
        type: finding.type,
        match: finding.match,
        preview: previewSecret(finding.match),
        lineText,
      };

      diagnostics.push(diag);
    }
  }

  diagnosticCollection.set(document.uri, diagnostics);
  statusBar.update(diagnostics.length);
}

// ---------------------------------------------------------------------------
// Allowlist loader
// ---------------------------------------------------------------------------
async function loadWorkspaceAllowlist(): Promise<RegExp[]> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) return [];

  const ignoreUri = vscode.Uri.joinPath(folders[0].uri, '.gitguardignore');
  try {
    const raw = await vscode.workspace.fs.readFile(ignoreUri);
    return parseGitguardignore(Buffer.from(raw).toString('utf8'));
  } catch {
    return [];
  }
}
