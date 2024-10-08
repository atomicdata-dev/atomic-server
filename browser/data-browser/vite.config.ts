import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';
import { VitePWA } from 'vite-plugin-pwa';
import webfontDownload from 'vite-plugin-webfont-dl';
import prismjs from 'vite-plugin-prismjs';
export default defineConfig({
  plugins: [
    webfontDownload(),
    react({ plugins: [['@swc/plugin-styled-components', {}]] }),
    VitePWA({
      registerType: 'autoUpdate',
      injectRegister: 'auto',
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
    prismjs({
      languages: ['typescript'],
      css: true,
      theme: 'default',
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
        entryFileNames: `assets/[name]-[hash].js`,
        chunkFileNames: `assets/chunk_[name]-[hash].js`,
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
