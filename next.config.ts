import type { NextConfig } from "next";

/**
 * Runs at the root of its own domain (canary.collinpfeifer.dev), so no basePath.
 *
 * output: "standalone" produces a self-contained server.js for the Docker image.
 */
const nextConfig: NextConfig = {
  output: "standalone",
};

export default nextConfig;
