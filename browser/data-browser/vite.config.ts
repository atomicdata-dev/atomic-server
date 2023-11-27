import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
  plugins: [
    react({
      babel: {
        plugins: [
          [
            'babel-plugin-styled-components',
            {
              fileName: false,
            },
          ],
        ],
      },
    }),
    VitePWA({
      registerType: 'autoUpdate',
      devOptions: {
        // If you want to test the service worker in development.
        // Note that if this was registered, you'll need to unregister it first
        // enabled: true
      },
      manifest: {
        name: 'Atomic Data Browser',
        short_name: 'Atomic',
        description:
          'The easiest way to create, share and model Linked Atomic Data.',
        theme_color: '#ffffff',
        icons: [
          {
            src: 'app_data/images/android-chrome-192x192.png',
            sizes: '192x192',
            type: 'image/png',
            purpose: 'any',
          },
          {
            src: 'app_data/images/android-chrome-512x512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'any',
          },
          {
            src: 'app_data/images/maskable_icon.png',
            sizes: '1024x1024',
            type: 'image/png',
            purpose: 'maskable',
          },
          {
            src: 'app_data/images/maskable_icon_x512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'maskable',
          },
          {
            src: 'app_data/images/maskable_icon_x384.png',
            sizes: '384x384',
            type: 'image/png',
            purpose: 'maskable',
          },
          {
            src: 'app_data/images/maskable_icon_x192.png',
            sizes: '192x192',
            type: 'image/png',
            purpose: 'maskable',
          },
          {
            src: 'app_data/images/maskable_icon_x128.png',
            sizes: '128x128',
            type: 'image/png',
            purpose: 'maskable',
          },
        ],
      },
      workbox: {
        // See https://github.com/atomicdata-dev/atomic-data-browser/issues/294
        globIgnores: ['**/index.html'],
        runtimeCaching: [
          {
            urlPattern: /^https:\/\/fonts\.googleapis\.com\/.*/i,
            handler: 'CacheFirst',
            options: {
              cacheName: 'google-fonts-cache',
              expiration: {
                maxEntries: 10,
                maxAgeSeconds: 60 * 60 * 24 * 365, // <== 365 days
              },
              cacheableResponse: {
                statuses: [0, 200],
              },
            },
          },
          {
            urlPattern: /^https:\/\/fonts\.gstatic\.com\/.*/i,
            handler: 'CacheFirst',
            options: {
              cacheName: 'gstatic-fonts-cache',
              expiration: {
                maxEntries: 10,
                maxAgeSeconds: 60 * 60 * 24 * 365, // <== 365 days
              },
              cacheableResponse: {
                statuses: [0, 200],
              },
            },
          },
        ],
      },
    }),
  ],
  optimizeDeps: {
    // this may help when linking + HMR is not working
    // exclude: ['@tomic/lib', '@tomic/react'],
  },
  build: {
    sourcemap: true,
    rollupOptions: {
      output: {
        entryFileNames: `assets/[name].js`,
        chunkFileNames: `assets/chunk_[name].js`,
        assetFileNames: `assets/[name].[ext]`,
      },
    },
  },
  server: {
    strictPort: true,
    host: true,
    hmr: {
      // Fixes an issue with HMR
      port: 5174,
    },
  },
});
