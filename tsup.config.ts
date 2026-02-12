import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/providers/cloudflare.ts', 'src/providers/loopia.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  minify: false,
});
