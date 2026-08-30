import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The PHP API is served by XAMPP. Point VITE_API_ORIGIN somewhere else if you
// run it with `php -S` instead — the app always calls a relative /api path, so
// only this proxy knows where the backend lives.
const target = process.env.VITE_API_ORIGIN || 'http://localhost';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target,
        changeOrigin: true,
        rewrite: (p) => (target === 'http://localhost' ? '/spendshield' + p : p),
      },
    },
  },
});
