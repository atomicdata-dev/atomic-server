/** @type {import('next').NextConfig} */
const nextConfig = {
  webpack: config => {
    config.resolve.extensionAlias = {
      '.js': ['.ts', '.tsx', '.js'],
    };

    return config;
  },
};

export default nextConfig;
