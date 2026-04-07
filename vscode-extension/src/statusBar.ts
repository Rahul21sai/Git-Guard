import * as vscode from 'vscode';

/**
 * GitGuard — Status bar manager
 * Shows 🔒 GitGuard: Clean or ⚠️ GitGuard: N secrets
 */
export class StatusBarManager {
  private readonly item: vscode.StatusBarItem;

  constructor(context: vscode.ExtensionContext) {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.item.command = 'workbench.actions.view.problems';
    this.item.tooltip = 'GitGuard — Click to open Problems panel';
    this.item.show();
    context.subscriptions.push(this.item);
    this.update(0);
  }

  update(secretCount: number): void {
    if (secretCount === 0) {
      this.item.text    = '$(lock) GitGuard: Clean';
      this.item.color   = new vscode.ThemeColor('gitDecoration.addedResourceForeground');
      this.item.backgroundColor = undefined;
    } else {
      this.item.text    = `$(warning) GitGuard: ${secretCount} secret${secretCount === 1 ? '' : 's'}`;
      this.item.color   = new vscode.ThemeColor('editorWarning.foreground');
      this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    }
  }

  dispose(): void {
    this.item.dispose();
  }
}
