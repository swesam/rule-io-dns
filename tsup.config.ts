import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/providers/cloudflare.ts',
    'src/providers/hetzner.ts',
    'src/providers/ionos.ts',
    'src/providers/ovh.ts',
    'src/providers/gandi.ts',
    'src/providers/loopia.ts',
    'src/providers/domeneshop.ts',
  ],
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  minify: false,
});
