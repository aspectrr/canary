import type { NextConfig } from "next";

/**
 * Mounted at collinpfeifer.dev/canary (path prefix).
 *
 * basePath makes every route, asset, and favicon live under /canary, so the
 * app shares a domain with another app without colliding. The reverse proxy
 * on collinpfeifer.dev must forward /canary/* to this app PRESERVING the path
 * (do not strip the prefix).
 *
 * output: "standalone" produces a self-contained server.js for the Docker
 * image (no node_modules needed at runtime).
 */
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "/canary";

const nextConfig: NextConfig = {
  basePath,
  output: "standalone",
  // Exposed to the client so fetch() calls can build the prefixed API path.
  env: { NEXT_PUBLIC_BASE_PATH: basePath },
};

export default nextConfig;
