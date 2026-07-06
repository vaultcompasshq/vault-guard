import { scanCommand } from './scan';

export async function checkCommand(files: string[]): Promise<number> {
  return scanCommand(files.length > 0 ? files : '.', 'text', false);
}
