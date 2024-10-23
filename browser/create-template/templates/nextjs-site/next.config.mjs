import path from 'path';

/** @type {import('next').NextConfig} */
const nextConfig = {
  // temporary workaround for using symlinked package with turbopack
  outputFileTracingRoot: path.join(import.meta.dirname, '../../../'),
  webpack: config => {
    config.resolve.extensionAlias = {
      '.js': ['.ts', '.tsx', '.js'],
    };

    return config;
  },
  experimental: {
    turbo: {},
  },
};

export default nextConfig;
