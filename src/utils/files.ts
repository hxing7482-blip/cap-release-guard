import { readdir, stat } from 'node:fs/promises';
import { extname, join } from 'node:path';

const textExtensions = new Set([
  '.css',
  '.html',
  '.htm',
  '.js',
  '.cjs',
  '.mjs',
  '.json',
  '.map',
  '.txt',
  '.xml',
  '.yaml',
  '.yml',
]);

export async function collectTextFiles(
  root: string,
  maximumBytes = 5 * 1024 * 1024
): Promise<string[]> {
  const rootStats = await stat(root);
  if (rootStats.isFile()) {
    return rootStats.size <= maximumBytes ? [root] : [];
  }
  if (!rootStats.isDirectory()) return [];

  const files: string[] = [];
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const fullPath = join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        await visit(fullPath);
        continue;
      }
      if (!entry.isFile() || !textExtensions.has(extname(entry.name).toLowerCase())) continue;
      const fileStats = await stat(fullPath);
      if (fileStats.size <= maximumBytes) files.push(fullPath);
    }
  }

  await visit(root);
  return files;
}
