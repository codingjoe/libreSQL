import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'LibreSQL',
      formats: ['es', 'cjs'],
      fileName: (format) => `index.${format === 'es' ? 'mjs' : 'cjs'}`,
    },
    rollupOptions: {
      // sql.js is a peer dependency — bundlers / CDN users supply it
      external: ['sql.js'],
      output: {
        globals: {
          'sql.js': 'initSqlJs',
        },
      },
    },
    sourcemap: true,
  },
});
