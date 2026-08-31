// Polyfill File for Node.js 18 where it's not a global
import { File } from 'node:buffer';

if (typeof globalThis.File === 'undefined') {
  (globalThis as Record<string, unknown>).File = File;
}