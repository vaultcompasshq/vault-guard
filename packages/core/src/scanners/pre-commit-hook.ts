import fs from 'fs';
import path from 'path';

export class PreCommitHook {
  private hookContent = `#!/bin/sh
# vault-guard pre-commit hook
echo "🔍 Running Vault Guard security scan..."
vault-guard scan

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ COMMIT BLOCKED: Secrets detected"
  echo "💡 Run 'vault-guard fix' to auto-fix issues"
  exit 1
fi

echo "✅ No secrets found, proceeding with commit"
`;

  /**
   * Install pre-commit hook in current git repository
   */
  install(): { success: boolean; message: string } {
    const gitDir = path.join(process.cwd(), '.git');

    if (!fs.existsSync(gitDir)) {
      return {
        success: false,
        message: 'Not a git repository'
      };
    }

    const hooksDir = path.join(gitDir, 'hooks');
    const hookPath = path.join(hooksDir, 'pre-commit');

    // Create hooks directory if it doesn't exist
    if (!fs.existsSync(hooksDir)) {
      fs.mkdirSync(hooksDir, { recursive: true });
    }

    // Check if hook already exists
    if (fs.existsSync(hookPath)) {
      const existingHook = fs.readFileSync(hookPath, 'utf-8');
      if (existingHook.includes('vault-guard')) {
        return {
          success: true,
          message: 'Hook already installed'
        };
      }
    }

    // Write hook file
    try {
      fs.writeFileSync(hookPath, this.hookContent, { mode: 0o755 });
      return {
        success: true,
        message: 'Pre-commit hook installed successfully'
      };
    } catch (error) {
      return {
        success: false,
        message: `Failed to install hook: ${error}`
      };
    }
  }

  /**
   * Uninstall pre-commit hook
   */
  uninstall(): { success: boolean; message: string } {
    const hookPath = path.join(process.cwd(), '.git', 'hooks', 'pre-commit');

    if (!fs.existsSync(hookPath)) {
      return {
        success: true,
        message: 'No hook to remove'
      };
    }

    try {
      fs.unlinkSync(hookPath);
      return {
        success: true,
        message: 'Pre-commit hook removed'
      };
    } catch (error) {
      return {
        success: false,
        message: `Failed to remove hook: ${error}`
      };
    }
  }

  /**
   * Check if hook is installed
   */
  isInstalled(): boolean {
    const hookPath = path.join(process.cwd(), '.git', 'hooks', 'pre-commit');
    if (!fs.existsSync(hookPath)) {
      return false;
    }

    const content = fs.readFileSync(hookPath, 'utf-8');
    return content.includes('vault-guard');
  }
}
