// src/tools/builtin-tools.ts
var BUILTIN_TOOL_EXECUTE_SQL = "execute_sql";
var BUILTIN_TOOL_SEARCH_OBJECTS = "search_objects";
var BUILTIN_TOOLS = [
  BUILTIN_TOOL_EXECUTE_SQL,
  BUILTIN_TOOL_SEARCH_OBJECTS
];

// src/connectors/interface.ts
var _ConnectorRegistry = class _ConnectorRegistry {
  /**
   * Register a new connector
   */
  static register(connector) {
    _ConnectorRegistry.connectors.set(connector.id, connector);
  }
  /**
   * Get a connector by ID
   */
  static getConnector(id) {
    return _ConnectorRegistry.connectors.get(id) || null;
  }
  /**
   * Get connector for a DSN string
   * Tries to find a connector that can handle the given DSN format
   */
  static getConnectorForDSN(dsn) {
    for (const connector of _ConnectorRegistry.connectors.values()) {
      if (connector.dsnParser.isValidDSN(dsn)) {
        return connector;
      }
    }
    return null;
  }
  /**
   * Get all available connector IDs
   */
  static getAvailableConnectors() {
    return Array.from(_ConnectorRegistry.connectors.keys());
  }
  /**
   * Get sample DSN for a specific connector
   */
  static getSampleDSN(connectorType) {
    const connector = _ConnectorRegistry.getConnector(connectorType);
    if (!connector) return null;
    return connector.dsnParser.getSampleDSN();
  }
  /**
   * Get all available sample DSNs
   */
  static getAllSampleDSNs() {
    const samples = {};
    for (const [id, connector] of _ConnectorRegistry.connectors.entries()) {
      samples[id] = connector.dsnParser.getSampleDSN();
    }
    return samples;
  }
};
_ConnectorRegistry.connectors = /* @__PURE__ */ new Map();
var ConnectorRegistry = _ConnectorRegistry;

// src/utils/ssh-tunnel.ts
import { Client } from "ssh2";
import { readFileSync as readFileSync2 } from "fs";
import { createServer } from "net";

// src/utils/ssh-config-parser.ts
import { readFileSync, realpathSync, statSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import SSHConfig from "ssh-config";
var DEFAULT_SSH_KEYS = [
  "~/.ssh/id_rsa",
  "~/.ssh/id_ed25519",
  "~/.ssh/id_ecdsa",
  "~/.ssh/id_dsa"
];
function expandTilde(filePath) {
  if (filePath.startsWith("~/")) {
    return join(homedir(), filePath.substring(2));
  }
  return filePath;
}
function resolveSymlink(filePath) {
  const expandedPath = expandTilde(filePath);
  try {
    return realpathSync(expandedPath);
  } catch {
    return expandedPath;
  }
}
function isFile(filePath) {
  try {
    const stat = statSync(filePath);
    return stat.isFile();
  } catch {
    return false;
  }
}
function findDefaultSSHKey() {
  for (const keyPath of DEFAULT_SSH_KEYS) {
    const resolvedPath = resolveSymlink(keyPath);
    if (isFile(resolvedPath)) {
      return resolvedPath;
    }
  }
  return void 0;
}
function parseSSHConfig(hostAlias, configPath) {
  const sshConfigPath = resolveSymlink(configPath);
  if (!isFile(sshConfigPath)) {
    return null;
  }
  try {
    const configContent = readFileSync(sshConfigPath, "utf8");
    const config = SSHConfig.parse(configContent);
    const hostConfig = config.compute(hostAlias);
    if (!hostConfig || !hostConfig.HostName && !hostConfig.User) {
      return null;
    }
    const sshConfig = {};
    if (hostConfig.HostName) {
      sshConfig.host = hostConfig.HostName;
    } else {
      sshConfig.host = hostAlias;
    }
    if (hostConfig.Port) {
      sshConfig.port = parseInt(hostConfig.Port, 10);
    }
    if (hostConfig.User) {
      sshConfig.username = hostConfig.User;
    }
    if (hostConfig.IdentityFile) {
      const identityFile = Array.isArray(hostConfig.IdentityFile) ? hostConfig.IdentityFile[0] : hostConfig.IdentityFile;
      const resolvedPath = resolveSymlink(identityFile);
      if (isFile(resolvedPath)) {
        sshConfig.privateKey = resolvedPath;
      }
    }
    if (!sshConfig.privateKey) {
      const defaultKey = findDefaultSSHKey();
      if (defaultKey) {
        sshConfig.privateKey = defaultKey;
      }
    }
    if (hostConfig.ProxyJump) {
      sshConfig.proxyJump = hostConfig.ProxyJump;
    }
    if (hostConfig.ProxyCommand) {
      console.error("Warning: ProxyCommand in SSH config is not supported by DBHub. Use ProxyJump instead.");
    }
    if (!sshConfig.host || !sshConfig.username) {
      return null;
    }
    return sshConfig;
  } catch (error) {
    console.error(`Error parsing SSH config: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}
function looksLikeSSHAlias(host) {
  if (host.includes(".")) {
    return false;
  }
  if (/^[\d:]+$/.test(host)) {
    return false;
  }
  if (/^[0-9a-fA-F:]+$/.test(host) && host.includes(":")) {
    return false;
  }
  return true;
}
function validatePort(port, jumpHostStr) {
  if (isNaN(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid port number in "${jumpHostStr}": port must be between 1 and 65535`);
  }
}
function parseJumpHost(jumpHostStr) {
  let username;
  let host;
  let port = 22;
  let remaining = jumpHostStr.trim();
  if (!remaining) {
    throw new Error("Jump host string cannot be empty");
  }
  const atIndex = remaining.indexOf("@");
  if (atIndex !== -1) {
    const extractedUsername = remaining.substring(0, atIndex).trim();
    if (extractedUsername) {
      username = extractedUsername;
    }
    remaining = remaining.substring(atIndex + 1);
  }
  if (remaining.startsWith("[")) {
    const closeBracket = remaining.indexOf("]");
    if (closeBracket !== -1) {
      host = remaining.substring(1, closeBracket);
      const afterBracket = remaining.substring(closeBracket + 1);
      if (afterBracket.startsWith(":")) {
        const parsedPort = parseInt(afterBracket.substring(1), 10);
        validatePort(parsedPort, jumpHostStr);
        port = parsedPort;
      }
    } else {
      throw new Error(`Invalid ProxyJump host "${jumpHostStr}": missing closing bracket in IPv6 address`);
    }
  } else {
    const lastColon = remaining.lastIndexOf(":");
    if (lastColon !== -1) {
      const potentialPort = remaining.substring(lastColon + 1);
      if (/^\d+$/.test(potentialPort)) {
        host = remaining.substring(0, lastColon);
        const parsedPort = parseInt(potentialPort, 10);
        validatePort(parsedPort, jumpHostStr);
        port = parsedPort;
      } else {
        host = remaining;
      }
    } else {
      host = remaining;
    }
  }
  if (!host) {
    throw new Error(`Invalid jump host format: "${jumpHostStr}" - host cannot be empty`);
  }
  return { host, port, username };
}
function parseJumpHosts(proxyJump) {
  if (!proxyJump || proxyJump.trim() === "" || proxyJump.toLowerCase() === "none") {
    return [];
  }
  return proxyJump.split(",").map((s) => s.trim()).filter((s) => s.length > 0).map(parseJumpHost);
}

// src/utils/ssh-tunnel.ts
var SSHTunnel = class {
  constructor() {
    this.sshClients = [];
    // All SSH clients in the chain
    this.localServer = null;
    this.tunnelInfo = null;
    this.isConnected = false;
  }
  /**
   * Establish an SSH tunnel, optionally through jump hosts (ProxyJump).
   * @param config SSH connection configuration
   * @param options Tunnel options including target host and port
   * @returns Promise resolving to tunnel information including local port
   */
  async establish(config, options) {
    if (this.isConnected) {
      throw new Error("SSH tunnel is already established");
    }
    this.isConnected = true;
    try {
      const jumpHosts = config.proxyJump ? parseJumpHosts(config.proxyJump) : [];
      let privateKeyBuffer;
      if (config.privateKey) {
        try {
          const resolvedKeyPath = resolveSymlink(config.privateKey);
          privateKeyBuffer = readFileSync2(resolvedKeyPath);
        } catch (error) {
          throw new Error(`Failed to read private key file: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      if (!config.password && !privateKeyBuffer) {
        throw new Error("Either password or privateKey must be provided for SSH authentication");
      }
      const finalClient = await this.establishChain(jumpHosts, config, privateKeyBuffer);
      return await this.createLocalTunnel(finalClient, options);
    } catch (error) {
      this.cleanup();
      throw error;
    }
  }
  /**
   * Establish a chain of SSH connections through jump hosts.
   * @returns The final SSH client connected to the target host
   */
  async establishChain(jumpHosts, targetConfig, privateKey) {
    let previousStream;
    for (let i = 0; i < jumpHosts.length; i++) {
      const jumpHost = jumpHosts[i];
      const nextHost = i + 1 < jumpHosts.length ? jumpHosts[i + 1] : { host: targetConfig.host, port: targetConfig.port || 22 };
      let client = null;
      let forwardStream;
      try {
        client = await this.connectToHost(
          {
            host: jumpHost.host,
            port: jumpHost.port,
            username: jumpHost.username || targetConfig.username
          },
          targetConfig.password,
          privateKey,
          targetConfig.passphrase,
          previousStream,
          `jump host ${i + 1}`,
          targetConfig.keepaliveInterval,
          targetConfig.keepaliveCountMax
        );
        console.error(`  \u2192 Forwarding through ${jumpHost.host}:${jumpHost.port} to ${nextHost.host}:${nextHost.port}`);
        forwardStream = await this.forwardTo(client, nextHost.host, nextHost.port);
      } catch (error) {
        if (client) {
          try {
            client.end();
          } catch {
          }
        }
        throw error;
      }
      this.sshClients.push(client);
      previousStream = forwardStream;
    }
    const finalClient = await this.connectToHost(
      {
        host: targetConfig.host,
        port: targetConfig.port || 22,
        username: targetConfig.username
      },
      targetConfig.password,
      privateKey,
      targetConfig.passphrase,
      previousStream,
      jumpHosts.length > 0 ? "target host" : void 0,
      targetConfig.keepaliveInterval,
      targetConfig.keepaliveCountMax
    );
    this.sshClients.push(finalClient);
    return finalClient;
  }
  /**
   * Connect to a single SSH host.
   */
  connectToHost(hostInfo, password, privateKey, passphrase, sock, label, keepaliveInterval, keepaliveCountMax) {
    return new Promise((resolve, reject) => {
      const client = new Client();
      const sshConfig = {
        host: hostInfo.host,
        port: hostInfo.port,
        username: hostInfo.username
      };
      if (password) {
        sshConfig.password = password;
      }
      if (privateKey) {
        sshConfig.privateKey = privateKey;
        if (passphrase) {
          sshConfig.passphrase = passphrase;
        }
      }
      if (sock) {
        sshConfig.sock = sock;
      }
      if (keepaliveInterval !== void 0 && keepaliveInterval > 0) {
        sshConfig.keepaliveInterval = keepaliveInterval * 1e3;
        sshConfig.keepaliveCountMax = keepaliveCountMax ?? 3;
      }
      const onError = (err) => {
        client.removeListener("ready", onReady);
        client.destroy();
        reject(new Error(`SSH connection error${label ? ` (${label})` : ""}: ${err.message}`));
      };
      const onReady = () => {
        client.removeListener("error", onError);
        const desc = label || `${hostInfo.host}:${hostInfo.port}`;
        console.error(`SSH connection established: ${desc}`);
        resolve(client);
      };
      client.on("error", onError);
      client.on("ready", onReady);
      client.connect(sshConfig);
    });
  }
  /**
   * Forward a connection through an SSH client to a target host.
   */
  forwardTo(client, targetHost, targetPort) {
    return new Promise((resolve, reject) => {
      client.forwardOut("127.0.0.1", 0, targetHost, targetPort, (err, stream) => {
        if (err) {
          reject(new Error(`SSH forward error: ${err.message}`));
          return;
        }
        resolve(stream);
      });
    });
  }
  /**
   * Create the local server that tunnels connections to the database.
   */
  createLocalTunnel(sshClient, options) {
    return new Promise((resolve, reject) => {
      let settled = false;
      this.localServer = createServer((localSocket) => {
        sshClient.forwardOut(
          "127.0.0.1",
          0,
          options.targetHost,
          options.targetPort,
          (err, stream) => {
            if (err) {
              console.error("SSH forward error:", err);
              localSocket.end();
              return;
            }
            localSocket.pipe(stream).pipe(localSocket);
            stream.on("error", (err2) => {
              console.error("SSH stream error:", err2);
              localSocket.end();
            });
            localSocket.on("error", (err2) => {
              console.error("Local socket error:", err2);
              stream.end();
            });
          }
        );
      });
      this.localServer.on("error", (err) => {
        if (!settled) {
          settled = true;
          reject(new Error(`Local server error: ${err.message}`));
        } else {
          console.error("Local server error after tunnel established:", err);
          this.cleanup();
        }
      });
      const localPort = options.localPort || 0;
      this.localServer.listen(localPort, "127.0.0.1", () => {
        const address = this.localServer.address();
        if (!address || typeof address === "string") {
          if (!settled) {
            settled = true;
            reject(new Error("Failed to get local server address"));
          }
          return;
        }
        this.tunnelInfo = {
          localPort: address.port,
          targetHost: options.targetHost,
          targetPort: options.targetPort
        };
        console.error(`SSH tunnel established: localhost:${address.port} \u2192 ${options.targetHost}:${options.targetPort}`);
        settled = true;
        resolve(this.tunnelInfo);
      });
    });
  }
  /**
   * Close the SSH tunnel and clean up resources
   */
  async close() {
    if (!this.isConnected) {
      return;
    }
    return new Promise((resolve) => {
      this.cleanup();
      console.error("SSH tunnel closed");
      resolve();
    });
  }
  /**
   * Clean up resources. Closes all SSH clients in reverse order (innermost first).
   */
  cleanup() {
    if (this.localServer) {
      this.localServer.close();
      this.localServer = null;
    }
    for (let i = this.sshClients.length - 1; i >= 0; i--) {
      try {
        this.sshClients[i].end();
      } catch {
      }
    }
    this.sshClients = [];
    this.tunnelInfo = null;
    this.isConnected = false;
  }
  /**
   * Get current tunnel information
   */
  getTunnelInfo() {
    return this.tunnelInfo;
  }
  /**
   * Check if tunnel is connected
   */
  getIsConnected() {
    return this.isConnected;
  }
};

// src/config/toml-loader.ts
import fs2 from "fs";
import path2 from "path";
import { homedir as homedir3 } from "os";
import toml from "@iarna/toml";

// src/config/env.ts
import dotenv from "dotenv";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { homedir as homedir2 } from "os";

// src/utils/safe-url.ts
var SafeURL = class {
  /**
   * Parse a URL and handle special characters in passwords
   * This is a safe alternative to the URL constructor
   * 
   * @param urlString - The DSN string to parse
   */
  constructor(urlString) {
    this.protocol = "";
    this.hostname = "";
    this.port = "";
    this.pathname = "";
    this.username = "";
    this.password = "";
    this.searchParams = /* @__PURE__ */ new Map();
    if (!urlString || urlString.trim() === "") {
      throw new Error("URL string cannot be empty");
    }
    try {
      const protocolSeparator = urlString.indexOf("://");
      if (protocolSeparator !== -1) {
        this.protocol = urlString.substring(0, protocolSeparator + 1);
        urlString = urlString.substring(protocolSeparator + 3);
      } else {
        throw new Error('Invalid URL format: missing protocol (e.g., "mysql://")');
      }
      const questionMarkIndex = urlString.indexOf("?");
      let queryParams = "";
      if (questionMarkIndex !== -1) {
        queryParams = urlString.substring(questionMarkIndex + 1);
        urlString = urlString.substring(0, questionMarkIndex);
        queryParams.split("&").forEach((pair) => {
          const parts = pair.split("=");
          if (parts.length === 2 && parts[0] && parts[1]) {
            this.searchParams.set(parts[0], decodeURIComponent(parts[1]));
          }
        });
      }
      const atIndex = urlString.indexOf("@");
      if (atIndex !== -1) {
        const auth = urlString.substring(0, atIndex);
        urlString = urlString.substring(atIndex + 1);
        const colonIndex2 = auth.indexOf(":");
        if (colonIndex2 !== -1) {
          this.username = auth.substring(0, colonIndex2);
          this.password = auth.substring(colonIndex2 + 1);
          this.username = decodeURIComponent(this.username);
          this.password = decodeURIComponent(this.password);
        } else {
          this.username = auth;
        }
      }
      const pathSeparatorIndex = urlString.indexOf("/");
      if (pathSeparatorIndex !== -1) {
        this.pathname = urlString.substring(pathSeparatorIndex);
        urlString = urlString.substring(0, pathSeparatorIndex);
      }
      const colonIndex = urlString.indexOf(":");
      if (colonIndex !== -1) {
        this.hostname = urlString.substring(0, colonIndex);
        this.port = urlString.substring(colonIndex + 1);
      } else {
        this.hostname = urlString;
      }
      if (this.protocol === "") {
        throw new Error("Invalid URL: protocol is required");
      }
    } catch (error) {
      throw new Error(`Failed to parse URL: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  /**
   * Helper method to safely get a parameter from query string
   * 
   * @param name - The parameter name to retrieve
   * @returns The parameter value or null if not found
   */
  getSearchParam(name) {
    return this.searchParams.has(name) ? this.searchParams.get(name) : null;
  }
  /**
   * Helper method to iterate over all parameters
   * 
   * @param callback - Function to call for each parameter
   */
  forEachSearchParam(callback) {
    this.searchParams.forEach((value, key) => callback(value, key));
  }
};

// src/utils/dsn-obfuscate.ts
function parseConnectionInfoFromDSN(dsn) {
  if (!dsn) {
    return null;
  }
  try {
    const type = getDatabaseTypeFromDSN(dsn);
    if (typeof type === "undefined") {
      return null;
    }
    if (type === "sqlite") {
      const prefix = "sqlite:///";
      if (dsn.length > prefix.length) {
        const rawPath = dsn.substring(prefix.length);
        const firstChar = rawPath[0];
        const isWindowsDrive = rawPath.length > 1 && rawPath[1] === ":";
        const isSpecialPath = firstChar === ":" || firstChar === "." || firstChar === "~" || isWindowsDrive;
        return {
          type,
          database: isSpecialPath ? rawPath : "/" + rawPath
        };
      }
      return { type };
    }
    const url = new SafeURL(dsn);
    const info = { type };
    if (url.hostname) {
      info.host = url.hostname;
    }
    if (url.port) {
      info.port = parseInt(url.port, 10);
    }
    if (url.pathname && url.pathname.length > 1) {
      info.database = url.pathname.substring(1);
    }
    if (url.username) {
      info.user = url.username;
    }
    return info;
  } catch {
    return null;
  }
}
function obfuscateDSNPassword(dsn) {
  if (!dsn) {
    return dsn;
  }
  try {
    const type = getDatabaseTypeFromDSN(dsn);
    if (type === "sqlite") {
      return dsn;
    }
    const url = new SafeURL(dsn);
    if (!url.password) {
      return dsn;
    }
    const obfuscatedPassword = "*".repeat(Math.min(url.password.length, 8));
    const protocol = dsn.split(":")[0];
    let result;
    if (url.username) {
      result = `${protocol}://${url.username}:${obfuscatedPassword}@${url.hostname}`;
    } else {
      result = `${protocol}://${obfuscatedPassword}@${url.hostname}`;
    }
    if (url.port) {
      result += `:${url.port}`;
    }
    result += url.pathname;
    if (url.searchParams.size > 0) {
      const params = [];
      url.forEachSearchParam((value, key) => {
        params.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
      });
      result += `?${params.join("&")}`;
    }
    return result;
  } catch {
    return dsn;
  }
}
function getDatabaseTypeFromDSN(dsn) {
  if (!dsn) {
    return void 0;
  }
  const protocol = dsn.split(":")[0];
  return protocolToConnectorType(protocol);
}
function protocolToConnectorType(protocol) {
  const mapping = {
    "postgres": "postgres",
    "postgresql": "postgres",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "sqlserver": "sqlserver",
    "sqlite": "sqlite"
  };
  return mapping[protocol];
}
function getDefaultPortForType(type) {
  const ports = {
    "postgres": 5432,
    "mysql": 3306,
    "mariadb": 3306,
    "sqlserver": 1433,
    "sqlite": void 0
  };
  return ports[type];
}

// src/config/env.ts
var __filename = fileURLToPath(import.meta.url);
var __dirname = path.dirname(__filename);
function parseCommandLineArgs() {
  const args = process.argv.slice(2);
  const parsedManually = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      const parts = arg.substring(2).split("=");
      const key = parts[0];
      if (key === "readonly") {
        console.error("\nERROR: --readonly flag is no longer supported.");
        console.error("Use dbhub.toml with [[tools]] configuration instead:\n");
        console.error("  [[sources]]");
        console.error('  id = "default"');
        console.error('  dsn = "..."\n');
        console.error("  [[tools]]");
        console.error('  name = "execute_sql"');
        console.error('  source = "default"');
        console.error("  readonly = true\n");
        console.error("See https://dbhub.ai/tools/execute-sql#read-only-mode for details.\n");
        process.exit(1);
      }
      if (key === "max-rows") {
        console.error("\nERROR: --max-rows flag is no longer supported.");
        console.error("Use dbhub.toml with [[tools]] configuration instead:\n");
        console.error("  [[sources]]");
        console.error('  id = "default"');
        console.error('  dsn = "..."\n');
        console.error("  [[tools]]");
        console.error('  name = "execute_sql"');
        console.error('  source = "default"');
        console.error("  max_rows = 1000\n");
        console.error("See https://dbhub.ai/tools/execute-sql#row-limiting for details.\n");
        process.exit(1);
      }
      const value = parts.length > 1 ? parts.slice(1).join("=") : void 0;
      if (value) {
        parsedManually[key] = value;
      } else if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
        parsedManually[key] = args[i + 1];
        i++;
      } else {
        parsedManually[key] = "true";
      }
    }
  }
  return parsedManually;
}
function loadEnvFiles() {
  const isDevelopment = process.env.NODE_ENV === "development" || process.argv[1]?.includes("tsx");
  const envFileNames = isDevelopment ? [".env.local", ".env"] : [".env"];
  const envPaths = [];
  for (const fileName of envFileNames) {
    envPaths.push(
      fileName,
      // Current working directory
      path.join(__dirname, "..", "..", fileName),
      // Two levels up (src/config -> src -> root)
      path.join(process.cwd(), fileName)
      // Explicit current working directory
    );
  }
  for (const envPath of envPaths) {
    console.error(`Checking for env file: ${envPath}`);
    if (fs.existsSync(envPath)) {
      dotenv.config({ path: envPath });
      if (process.env.READONLY !== void 0) {
        console.error("\nERROR: READONLY environment variable is no longer supported.");
        console.error("Use dbhub.toml with [[tools]] configuration instead:\n");
        console.error("  [[sources]]");
        console.error('  id = "default"');
        console.error('  dsn = "..."\n');
        console.error("  [[tools]]");
        console.error('  name = "execute_sql"');
        console.error('  source = "default"');
        console.error("  readonly = true\n");
        console.error("See https://dbhub.ai/tools/execute-sql#read-only-mode for details.\n");
        process.exit(1);
      }
      if (process.env.MAX_ROWS !== void 0) {
        console.error("\nERROR: MAX_ROWS environment variable is no longer supported.");
        console.error("Use dbhub.toml with [[tools]] configuration instead:\n");
        console.error("  [[sources]]");
        console.error('  id = "default"');
        console.error('  dsn = "..."\n');
        console.error("  [[tools]]");
        console.error('  name = "execute_sql"');
        console.error('  source = "default"');
        console.error("  max_rows = 1000\n");
        console.error("See https://dbhub.ai/tools/execute-sql#row-limiting for details.\n");
        process.exit(1);
      }
      return path.basename(envPath);
    }
  }
  return null;
}
function isDemoMode() {
  const args = parseCommandLineArgs();
  return args.demo === "true";
}
function buildDSNFromEnvParams() {
  const dbType = process.env.DB_TYPE;
  const dbHost = process.env.DB_HOST;
  const dbUser = process.env.DB_USER;
  const dbPassword = process.env.DB_PASSWORD;
  const dbName = process.env.DB_NAME;
  const dbPort = process.env.DB_PORT;
  if (dbType?.toLowerCase() === "sqlite") {
    if (!dbName) {
      return null;
    }
  } else {
    if (!dbType || !dbHost || !dbUser || !dbPassword || !dbName) {
      return null;
    }
  }
  const supportedTypes = ["postgres", "postgresql", "mysql", "mariadb", "sqlserver", "sqlite"];
  if (!supportedTypes.includes(dbType.toLowerCase())) {
    throw new Error(`Unsupported DB_TYPE: ${dbType}. Supported types: ${supportedTypes.join(", ")}`);
  }
  let port = dbPort;
  if (!port) {
    switch (dbType.toLowerCase()) {
      case "postgres":
      case "postgresql":
        port = "5432";
        break;
      case "mysql":
      case "mariadb":
        port = "3306";
        break;
      case "sqlserver":
        port = "1433";
        break;
      case "sqlite":
        return {
          dsn: `sqlite:///${dbName}`,
          source: "individual environment variables"
        };
      default:
        throw new Error(`Unknown database type for port determination: ${dbType}`);
    }
  }
  const user = dbUser;
  const password = dbPassword;
  const dbNameStr = dbName;
  const encodedUser = encodeURIComponent(user);
  const encodedPassword = encodeURIComponent(password);
  const encodedDbName = encodeURIComponent(dbNameStr);
  const protocol = dbType.toLowerCase() === "postgresql" ? "postgres" : dbType.toLowerCase();
  const dsn = `${protocol}://${encodedUser}:${encodedPassword}@${dbHost}:${port}/${encodedDbName}`;
  return {
    dsn,
    source: "individual environment variables"
  };
}
function resolveDSN() {
  const args = parseCommandLineArgs();
  if (isDemoMode()) {
    return {
      dsn: "sqlite:///:memory:",
      source: "demo mode",
      isDemo: true
    };
  }
  if (args.dsn) {
    return { dsn: args.dsn, source: "command line argument" };
  }
  if (process.env.DSN) {
    return { dsn: process.env.DSN, source: "environment variable" };
  }
  const envParamsResult = buildDSNFromEnvParams();
  if (envParamsResult) {
    return envParamsResult;
  }
  const loadedEnvFile = loadEnvFiles();
  if (loadedEnvFile && process.env.DSN) {
    return { dsn: process.env.DSN, source: `${loadedEnvFile} file` };
  }
  if (loadedEnvFile) {
    const envFileParamsResult = buildDSNFromEnvParams();
    if (envFileParamsResult) {
      return {
        dsn: envFileParamsResult.dsn,
        source: `${loadedEnvFile} file (individual parameters)`
      };
    }
  }
  return null;
}
function resolveTransport() {
  const args = parseCommandLineArgs();
  if (args.transport) {
    const type = args.transport === "http" ? "http" : "stdio";
    return { type, source: "command line argument" };
  }
  if (process.env.TRANSPORT) {
    const type = process.env.TRANSPORT === "http" ? "http" : "stdio";
    return { type, source: "environment variable" };
  }
  return { type: "stdio", source: "default" };
}
function resolvePort() {
  const args = parseCommandLineArgs();
  if (args.port) {
    const port = parseInt(args.port, 10);
    return { port, source: "command line argument" };
  }
  if (process.env.PORT) {
    const port = parseInt(process.env.PORT, 10);
    return { port, source: "environment variable" };
  }
  return { port: 8080, source: "default" };
}
function redactDSN(dsn) {
  try {
    const url = new URL(dsn);
    if (url.password) {
      url.password = "*******";
    }
    return url.toString();
  } catch (error) {
    return dsn.replace(/\/\/([^:]+):([^@]+)@/, "//$1:***@");
  }
}
function resolveId() {
  const args = parseCommandLineArgs();
  if (args.id) {
    return { id: args.id, source: "command line argument" };
  }
  if (process.env.ID) {
    return { id: process.env.ID, source: "environment variable" };
  }
  return null;
}
function resolveSSHConfig() {
  const args = parseCommandLineArgs();
  const hasSSHArgs = args["ssh-host"] || process.env.SSH_HOST;
  if (!hasSSHArgs) {
    return null;
  }
  let config = {};
  let sources = [];
  let sshConfigHost;
  if (args["ssh-host"]) {
    sshConfigHost = args["ssh-host"];
    config.host = args["ssh-host"];
    sources.push("ssh-host from command line");
  } else if (process.env.SSH_HOST) {
    sshConfigHost = process.env.SSH_HOST;
    config.host = process.env.SSH_HOST;
    sources.push("SSH_HOST from environment");
  }
  if (sshConfigHost && looksLikeSSHAlias(sshConfigHost)) {
    const sshConfigPath = path.join(homedir2(), ".ssh", "config");
    console.error(`Attempting to parse SSH config for host '${sshConfigHost}' from: ${sshConfigPath}`);
    const sshConfigData = parseSSHConfig(sshConfigHost, sshConfigPath);
    if (sshConfigData) {
      config = { ...sshConfigData };
      sources.push(`SSH config for host '${sshConfigHost}'`);
    }
  }
  if (args["ssh-port"]) {
    config.port = parseInt(args["ssh-port"], 10);
    sources.push("ssh-port from command line");
  } else if (process.env.SSH_PORT) {
    config.port = parseInt(process.env.SSH_PORT, 10);
    sources.push("SSH_PORT from environment");
  }
  if (args["ssh-user"]) {
    config.username = args["ssh-user"];
    sources.push("ssh-user from command line");
  } else if (process.env.SSH_USER) {
    config.username = process.env.SSH_USER;
    sources.push("SSH_USER from environment");
  }
  if (args["ssh-password"]) {
    config.password = args["ssh-password"];
    sources.push("ssh-password from command line");
  } else if (process.env.SSH_PASSWORD) {
    config.password = process.env.SSH_PASSWORD;
    sources.push("SSH_PASSWORD from environment");
  }
  if (args["ssh-key"]) {
    config.privateKey = args["ssh-key"];
    if (config.privateKey.startsWith("~/")) {
      config.privateKey = path.join(process.env.HOME || "", config.privateKey.substring(2));
    }
    sources.push("ssh-key from command line");
  } else if (process.env.SSH_KEY) {
    config.privateKey = process.env.SSH_KEY;
    if (config.privateKey.startsWith("~/")) {
      config.privateKey = path.join(process.env.HOME || "", config.privateKey.substring(2));
    }
    sources.push("SSH_KEY from environment");
  }
  if (args["ssh-passphrase"]) {
    config.passphrase = args["ssh-passphrase"];
    sources.push("ssh-passphrase from command line");
  } else if (process.env.SSH_PASSPHRASE) {
    config.passphrase = process.env.SSH_PASSPHRASE;
    sources.push("SSH_PASSPHRASE from environment");
  }
  if (args["ssh-proxy-jump"]) {
    config.proxyJump = args["ssh-proxy-jump"];
    sources.push("ssh-proxy-jump from command line");
  } else if (process.env.SSH_PROXY_JUMP) {
    config.proxyJump = process.env.SSH_PROXY_JUMP;
    sources.push("SSH_PROXY_JUMP from environment");
  }
  if (args["ssh-keepalive-interval"]) {
    config.keepaliveInterval = parseInt(args["ssh-keepalive-interval"], 10);
    sources.push("ssh-keepalive-interval from command line");
  } else if (process.env.SSH_KEEPALIVE_INTERVAL) {
    config.keepaliveInterval = parseInt(process.env.SSH_KEEPALIVE_INTERVAL, 10);
    sources.push("SSH_KEEPALIVE_INTERVAL from environment");
  }
  if (args["ssh-keepalive-count-max"]) {
    config.keepaliveCountMax = parseInt(args["ssh-keepalive-count-max"], 10);
    sources.push("ssh-keepalive-count-max from command line");
  } else if (process.env.SSH_KEEPALIVE_COUNT_MAX) {
    config.keepaliveCountMax = parseInt(process.env.SSH_KEEPALIVE_COUNT_MAX, 10);
    sources.push("SSH_KEEPALIVE_COUNT_MAX from environment");
  }
  if (!config.host || !config.username) {
    throw new Error("SSH tunnel configuration requires at least --ssh-host and --ssh-user");
  }
  if (!config.password && !config.privateKey) {
    throw new Error("SSH tunnel configuration requires either --ssh-password or --ssh-key for authentication");
  }
  return {
    config,
    source: sources.join(", ")
  };
}
async function resolveSourceConfigs() {
  if (!isDemoMode()) {
    const tomlConfig = loadTomlConfig();
    if (tomlConfig) {
      const idData = resolveId();
      if (idData) {
        throw new Error(
          "The --id flag cannot be used with TOML configuration. TOML config defines source IDs directly. Either remove the --id flag or use command-line DSN configuration instead."
        );
      }
      return tomlConfig;
    }
  }
  const dsnResult = resolveDSN();
  if (dsnResult) {
    let dsnUrl;
    try {
      dsnUrl = new SafeURL(dsnResult.dsn);
    } catch (error) {
      throw new Error(
        `Invalid DSN format: ${dsnResult.dsn}. Expected format: protocol://[user[:password]@]host[:port]/database`
      );
    }
    const protocol = dsnUrl.protocol.replace(":", "");
    let dbType;
    if (protocol === "postgresql" || protocol === "postgres") {
      dbType = "postgres";
    } else if (protocol === "mysql") {
      dbType = "mysql";
    } else if (protocol === "mariadb") {
      dbType = "mariadb";
    } else if (protocol === "sqlserver") {
      dbType = "sqlserver";
    } else if (protocol === "sqlite") {
      dbType = "sqlite";
    } else {
      throw new Error(`Unsupported database type in DSN: ${protocol}`);
    }
    const idData = resolveId();
    const sourceId = idData?.id || "default";
    const source = {
      id: sourceId,
      type: dbType,
      dsn: dsnResult.dsn
    };
    const connectionInfo = parseConnectionInfoFromDSN(dsnResult.dsn);
    if (connectionInfo) {
      if (connectionInfo.host) {
        source.host = connectionInfo.host;
      }
      if (connectionInfo.port !== void 0) {
        source.port = connectionInfo.port;
      }
      if (connectionInfo.database) {
        source.database = connectionInfo.database;
      }
      if (connectionInfo.user) {
        source.user = connectionInfo.user;
      }
    }
    const sshResult = resolveSSHConfig();
    if (sshResult) {
      source.ssh_host = sshResult.config.host;
      source.ssh_port = sshResult.config.port;
      source.ssh_user = sshResult.config.username;
      source.ssh_password = sshResult.config.password;
      source.ssh_key = sshResult.config.privateKey;
      source.ssh_passphrase = sshResult.config.passphrase;
      source.ssh_keepalive_interval = sshResult.config.keepaliveInterval;
      source.ssh_keepalive_count_max = sshResult.config.keepaliveCountMax;
    }
    if (dsnResult.isDemo) {
      const { getSqliteInMemorySetupSql } = await import("./demo-loader-PSMTLZ2T.js");
      source.init_script = getSqliteInMemorySetupSql();
    }
    return {
      sources: [source],
      tools: [],
      source: dsnResult.isDemo ? "demo mode" : dsnResult.source
    };
  }
  return null;
}

// src/config/toml-loader.ts
function loadTomlConfig() {
  const configPath = resolveTomlConfigPath();
  if (!configPath) {
    return null;
  }
  try {
    const fileContent = fs2.readFileSync(configPath, "utf-8");
    const parsedToml = toml.parse(fileContent);
    if (!Array.isArray(parsedToml.sources)) {
      throw new Error(
        `Configuration file ${configPath}: must contain a [[sources]] array. Use [[sources]] syntax for array of tables in TOML.`
      );
    }
    const sources = processSourceConfigs(parsedToml.sources, configPath);
    validateTomlConfig({ ...parsedToml, sources }, configPath);
    return {
      sources,
      tools: parsedToml.tools,
      source: path2.basename(configPath)
    };
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(
        `Failed to load TOML configuration from ${configPath}: ${error.message}`
      );
    }
    throw error;
  }
}
function resolveTomlConfigPath() {
  const args = parseCommandLineArgs();
  if (args.config) {
    const configPath = expandHomeDir(args.config);
    if (!fs2.existsSync(configPath)) {
      throw new Error(
        `Configuration file specified by --config flag not found: ${configPath}`
      );
    }
    return configPath;
  }
  const defaultConfigPath = path2.join(process.cwd(), "dbhub.toml");
  if (fs2.existsSync(defaultConfigPath)) {
    return defaultConfigPath;
  }
  return null;
}
function validateTomlConfig(config, configPath) {
  if (!config.sources) {
    throw new Error(
      `Configuration file ${configPath} must contain a [[sources]] array. Example:

[[sources]]
id = "my_db"
dsn = "postgres://..."`
    );
  }
  if (config.sources.length === 0) {
    throw new Error(
      `Configuration file ${configPath}: sources array cannot be empty. Please define at least one source with [[sources]].`
    );
  }
  const ids = /* @__PURE__ */ new Set();
  const duplicates = [];
  for (const source of config.sources) {
    if (!source.id) {
      throw new Error(
        `Configuration file ${configPath}: each source must have an 'id' field. Example: [[sources]]
id = "my_db"`
      );
    }
    if (ids.has(source.id)) {
      duplicates.push(source.id);
    } else {
      ids.add(source.id);
    }
  }
  if (duplicates.length > 0) {
    throw new Error(
      `Configuration file ${configPath}: duplicate source IDs found: ${duplicates.join(", ")}. Each source must have a unique 'id' field.`
    );
  }
  for (const source of config.sources) {
    validateSourceConfig(source, configPath);
  }
  if (config.tools) {
    validateToolsConfig(config.tools, config.sources, configPath);
  }
}
function validateToolsConfig(tools, sources, configPath) {
  const toolSourcePairs = /* @__PURE__ */ new Set();
  for (const tool of tools) {
    if (!tool.name) {
      throw new Error(
        `Configuration file ${configPath}: all tools must have a 'name' field`
      );
    }
    if (!tool.source) {
      throw new Error(
        `Configuration file ${configPath}: tool '${tool.name}' must have a 'source' field`
      );
    }
    const pairKey = `${tool.name}:${tool.source}`;
    if (toolSourcePairs.has(pairKey)) {
      throw new Error(
        `Configuration file ${configPath}: duplicate tool configuration found for '${tool.name}' on source '${tool.source}'`
      );
    }
    toolSourcePairs.add(pairKey);
    if (!sources.some((s) => s.id === tool.source)) {
      throw new Error(
        `Configuration file ${configPath}: tool '${tool.name}' references unknown source '${tool.source}'`
      );
    }
    const isBuiltin = BUILTIN_TOOLS.includes(tool.name);
    const isExecuteSql = tool.name === BUILTIN_TOOL_EXECUTE_SQL;
    if (isBuiltin) {
      if (tool.description || tool.statement || tool.parameters) {
        throw new Error(
          `Configuration file ${configPath}: built-in tool '${tool.name}' cannot have description, statement, or parameters fields`
        );
      }
      if (!isExecuteSql && (tool.readonly !== void 0 || tool.max_rows !== void 0)) {
        throw new Error(
          `Configuration file ${configPath}: tool '${tool.name}' cannot have readonly or max_rows fields (these are only valid for ${BUILTIN_TOOL_EXECUTE_SQL} tool)`
        );
      }
    } else {
      if (!tool.description || !tool.statement) {
        throw new Error(
          `Configuration file ${configPath}: custom tool '${tool.name}' must have 'description' and 'statement' fields`
        );
      }
    }
    if (tool.max_rows !== void 0) {
      if (typeof tool.max_rows !== "number" || tool.max_rows <= 0) {
        throw new Error(
          `Configuration file ${configPath}: tool '${tool.name}' has invalid max_rows. Must be a positive integer.`
        );
      }
    }
    if (tool.readonly !== void 0 && typeof tool.readonly !== "boolean") {
      throw new Error(
        `Configuration file ${configPath}: tool '${tool.name}' has invalid readonly. Must be a boolean (true or false).`
      );
    }
  }
}
function validateSourceConfig(source, configPath) {
  const hasConnectionParams = source.type && (source.type === "sqlite" ? source.database : source.host);
  if (!source.dsn && !hasConnectionParams) {
    throw new Error(
      `Configuration file ${configPath}: source '${source.id}' must have either:
  - 'dsn' field (e.g., dsn = "postgres://user:pass@host:5432/dbname")
  - OR connection parameters (type, host, database, user, password)
  - For SQLite: type = "sqlite" and database path`
    );
  }
  if (source.type) {
    const validTypes = ["postgres", "mysql", "mariadb", "sqlserver", "sqlite"];
    if (!validTypes.includes(source.type)) {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has invalid type '${source.type}'. Valid types: ${validTypes.join(", ")}`
      );
    }
  }
  if (source.connection_timeout !== void 0) {
    if (typeof source.connection_timeout !== "number" || source.connection_timeout <= 0) {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has invalid connection_timeout. Must be a positive number (in seconds).`
      );
    }
  }
  if (source.query_timeout !== void 0) {
    if (typeof source.query_timeout !== "number" || source.query_timeout <= 0) {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has invalid query_timeout. Must be a positive number (in seconds).`
      );
    }
  }
  if (source.ssh_port !== void 0) {
    if (typeof source.ssh_port !== "number" || source.ssh_port <= 0 || source.ssh_port > 65535) {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has invalid ssh_port. Must be between 1 and 65535.`
      );
    }
  }
  if (source.sslmode !== void 0) {
    if (source.type === "sqlite") {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has sslmode but SQLite does not support SSL. Remove the sslmode field for SQLite sources.`
      );
    }
    const validSslModes = ["disable", "require"];
    if (!validSslModes.includes(source.sslmode)) {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has invalid sslmode '${source.sslmode}'. Valid values: ${validSslModes.join(", ")}`
      );
    }
  }
  if (source.authentication !== void 0) {
    if (source.type !== "sqlserver") {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has authentication but it is only supported for SQL Server.`
      );
    }
    const validAuthMethods = ["ntlm", "azure-active-directory-access-token"];
    if (!validAuthMethods.includes(source.authentication)) {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has invalid authentication '${source.authentication}'. Valid values: ${validAuthMethods.join(", ")}`
      );
    }
    if (source.authentication === "ntlm" && !source.domain) {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' uses NTLM authentication but 'domain' is not specified.`
      );
    }
  }
  if (source.domain !== void 0) {
    if (source.type !== "sqlserver") {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has domain but it is only supported for SQL Server.`
      );
    }
    if (source.authentication === void 0) {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has domain but authentication is not set. Add authentication = "ntlm" to use Windows domain authentication.`
      );
    }
    if (source.authentication !== "ntlm") {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has domain but authentication is set to '${source.authentication}'. Domain is only valid with authentication = "ntlm".`
      );
    }
  }
  if (source.search_path !== void 0) {
    if (source.type !== "postgres") {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has 'search_path' but it is only supported for PostgreSQL sources.`
      );
    }
    if (typeof source.search_path !== "string" || source.search_path.trim().length === 0) {
      throw new Error(
        `Configuration file ${configPath}: source '${source.id}' has invalid search_path. Must be a non-empty string of comma-separated schema names (e.g., "myschema,public").`
      );
    }
  }
  if (source.readonly !== void 0) {
    throw new Error(
      `Configuration file ${configPath}: source '${source.id}' has 'readonly' field, but readonly must be configured per-tool, not per-source. Move 'readonly' to [[tools]] configuration instead.`
    );
  }
  if (source.max_rows !== void 0) {
    throw new Error(
      `Configuration file ${configPath}: source '${source.id}' has 'max_rows' field, but max_rows must be configured per-tool, not per-source. Move 'max_rows' to [[tools]] configuration instead.`
    );
  }
}
function processSourceConfigs(sources, configPath) {
  return sources.map((source) => {
    const processed = { ...source };
    if (processed.ssh_key) {
      processed.ssh_key = expandHomeDir(processed.ssh_key);
    }
    if (processed.type === "sqlite" && processed.database) {
      processed.database = expandHomeDir(processed.database);
    }
    if (processed.dsn && processed.dsn.startsWith("sqlite:///~")) {
      processed.dsn = `sqlite:///${expandHomeDir(processed.dsn.substring(11))}`;
    }
    if (processed.dsn) {
      const connectionInfo = parseConnectionInfoFromDSN(processed.dsn);
      if (connectionInfo) {
        if (!processed.type && connectionInfo.type) {
          processed.type = connectionInfo.type;
        }
        if (!processed.host && connectionInfo.host) {
          processed.host = connectionInfo.host;
        }
        if (processed.port === void 0 && connectionInfo.port !== void 0) {
          processed.port = connectionInfo.port;
        }
        if (!processed.database && connectionInfo.database) {
          processed.database = connectionInfo.database;
        }
        if (!processed.user && connectionInfo.user) {
          processed.user = connectionInfo.user;
        }
      }
    }
    return processed;
  });
}
function expandHomeDir(filePath) {
  if (filePath.startsWith("~/")) {
    return path2.join(homedir3(), filePath.substring(2));
  }
  return filePath;
}
function buildDSNFromSource(source) {
  if (source.dsn) {
    return source.dsn;
  }
  if (!source.type) {
    throw new Error(
      `Source '${source.id}': 'type' field is required when 'dsn' is not provided`
    );
  }
  if (source.type === "sqlite") {
    if (!source.database) {
      throw new Error(
        `Source '${source.id}': 'database' field is required for SQLite`
      );
    }
    return `sqlite:///${source.database}`;
  }
  const passwordRequired = source.authentication !== "azure-active-directory-access-token";
  if (!source.host || !source.user || !source.database) {
    throw new Error(
      `Source '${source.id}': missing required connection parameters. Required: type, host, user, database`
    );
  }
  if (passwordRequired && !source.password) {
    throw new Error(
      `Source '${source.id}': password is required. (Password is optional only for azure-active-directory-access-token authentication)`
    );
  }
  const port = source.port || getDefaultPortForType(source.type);
  if (!port) {
    throw new Error(`Source '${source.id}': unable to determine port`);
  }
  const encodedUser = encodeURIComponent(source.user);
  const encodedPassword = source.password ? encodeURIComponent(source.password) : "";
  const encodedDatabase = encodeURIComponent(source.database);
  let dsn = `${source.type}://${encodedUser}:${encodedPassword}@${source.host}:${port}/${encodedDatabase}`;
  const queryParams = [];
  if (source.type === "sqlserver") {
    if (source.instanceName) {
      queryParams.push(`instanceName=${encodeURIComponent(source.instanceName)}`);
    }
    if (source.authentication) {
      queryParams.push(`authentication=${encodeURIComponent(source.authentication)}`);
    }
    if (source.domain) {
      queryParams.push(`domain=${encodeURIComponent(source.domain)}`);
    }
  }
  if (source.sslmode && source.type !== "sqlite") {
    queryParams.push(`sslmode=${source.sslmode}`);
  }
  if (queryParams.length > 0) {
    dsn += `?${queryParams.join("&")}`;
  }
  return dsn;
}

// src/connectors/manager.ts
var managerInstance = null;
var ConnectorManager = class {
  // Prevent race conditions
  constructor() {
    // Maps for multi-source support
    this.connectors = /* @__PURE__ */ new Map();
    this.sshTunnels = /* @__PURE__ */ new Map();
    this.sourceConfigs = /* @__PURE__ */ new Map();
    // Store original source configs
    this.sourceIds = [];
    // Ordered list of source IDs (first is default)
    // Lazy connection support
    this.lazySources = /* @__PURE__ */ new Map();
    // Sources pending lazy connection
    this.pendingConnections = /* @__PURE__ */ new Map();
    if (!managerInstance) {
      managerInstance = this;
    }
  }
  /**
   * Initialize and connect to multiple databases using source configurations
   * This is the new multi-source connection method
   */
  async connectWithSources(sources) {
    if (sources.length === 0) {
      throw new Error("No sources provided");
    }
    const eagerSources = sources.filter((s) => !s.lazy);
    const lazySources = sources.filter((s) => s.lazy);
    if (eagerSources.length > 0) {
      console.error(`Connecting to ${eagerSources.length} database source(s)...`);
    }
    for (const source of eagerSources) {
      await this.connectSource(source);
    }
    for (const source of lazySources) {
      this.registerLazySource(source);
    }
  }
  /**
   * Register a lazy source without establishing connection
   * Connection will be established on first use via ensureConnected()
   */
  registerLazySource(source) {
    const sourceId = source.id;
    const dsn = buildDSNFromSource(source);
    console.error(`  - ${sourceId}: ${redactDSN(dsn)} (lazy, will connect on first use)`);
    this.lazySources.set(sourceId, source);
    this.sourceConfigs.set(sourceId, source);
    this.sourceIds.push(sourceId);
  }
  /**
   * Ensure a source is connected (handles lazy connection on demand)
   * Safe to call multiple times - uses promise-based deduplication so concurrent calls share the same connection attempt
   */
  async ensureConnected(sourceId) {
    const id = sourceId || this.sourceIds[0];
    if (this.connectors.has(id)) {
      return;
    }
    const lazySource = this.lazySources.get(id);
    if (!lazySource) {
      if (sourceId) {
        throw new Error(
          `Source '${sourceId}' not found. Available sources: ${this.sourceIds.join(", ")}`
        );
      } else {
        throw new Error("No sources configured. Call connectWithSources() first.");
      }
    }
    const pending = this.pendingConnections.get(id);
    if (pending) {
      return pending;
    }
    const connectionPromise = (async () => {
      try {
        console.error(`Lazy connecting to source '${id}'...`);
        await this.connectSource(lazySource);
        this.lazySources.delete(id);
      } finally {
        this.pendingConnections.delete(id);
      }
    })();
    this.pendingConnections.set(id, connectionPromise);
    return connectionPromise;
  }
  /**
   * Static method to ensure a source is connected (for tool handlers)
   */
  static async ensureConnected(sourceId) {
    if (!managerInstance) {
      throw new Error("ConnectorManager not initialized");
    }
    return managerInstance.ensureConnected(sourceId);
  }
  /**
   * Connect to a single source (helper for connectWithSources)
   */
  async connectSource(source) {
    const sourceId = source.id;
    const dsn = buildDSNFromSource(source);
    console.error(`  - ${sourceId}: ${redactDSN(dsn)}`);
    let actualDSN = dsn;
    if (source.ssh_host) {
      if (!source.ssh_user) {
        throw new Error(
          `Source '${sourceId}': SSH tunnel requires ssh_user`
        );
      }
      const sshConfig = {
        host: source.ssh_host,
        port: source.ssh_port || 22,
        username: source.ssh_user,
        password: source.ssh_password,
        privateKey: source.ssh_key,
        passphrase: source.ssh_passphrase,
        proxyJump: source.ssh_proxy_jump,
        keepaliveInterval: source.ssh_keepalive_interval,
        keepaliveCountMax: source.ssh_keepalive_count_max
      };
      if (!sshConfig.password && !sshConfig.privateKey) {
        throw new Error(
          `Source '${sourceId}': SSH tunnel requires either ssh_password or ssh_key`
        );
      }
      const url = new URL(dsn);
      const targetHost = url.hostname;
      const targetPort = parseInt(url.port) || this.getDefaultPort(dsn);
      const tunnel = new SSHTunnel();
      const tunnelInfo = await tunnel.establish(sshConfig, {
        targetHost,
        targetPort
      });
      url.hostname = "127.0.0.1";
      url.port = tunnelInfo.localPort.toString();
      actualDSN = url.toString();
      this.sshTunnels.set(sourceId, tunnel);
      console.error(
        `  SSH tunnel established through localhost:${tunnelInfo.localPort}`
      );
    }
    const connectorPrototype = ConnectorRegistry.getConnectorForDSN(actualDSN);
    if (!connectorPrototype) {
      throw new Error(
        `Source '${sourceId}': No connector found for DSN: ${actualDSN}`
      );
    }
    const connector = connectorPrototype.clone();
    connector.sourceId = sourceId;
    const config = {};
    if (source.connection_timeout !== void 0) {
      config.connectionTimeoutSeconds = source.connection_timeout;
    }
    if (source.query_timeout !== void 0 && connector.id !== "sqlite") {
      config.queryTimeoutSeconds = source.query_timeout;
    }
    if (source.readonly !== void 0) {
      config.readonly = source.readonly;
    }
    if (source.search_path) {
      config.searchPath = source.search_path;
    }
    await connector.connect(actualDSN, source.init_script, config);
    this.connectors.set(sourceId, connector);
    if (!this.sourceIds.includes(sourceId)) {
      this.sourceIds.push(sourceId);
    }
    this.sourceConfigs.set(sourceId, source);
  }
  /**
   * Close all database connections
   */
  async disconnect() {
    for (const [sourceId, connector] of this.connectors.entries()) {
      try {
        await connector.disconnect();
        console.error(`Disconnected from source '${sourceId || "(default)"}'`);
      } catch (error) {
        console.error(`Error disconnecting from source '${sourceId}':`, error);
      }
    }
    for (const [sourceId, tunnel] of this.sshTunnels.entries()) {
      try {
        await tunnel.close();
      } catch (error) {
        console.error(`Error closing SSH tunnel for source '${sourceId}':`, error);
      }
    }
    this.connectors.clear();
    this.sshTunnels.clear();
    this.sourceConfigs.clear();
    this.lazySources.clear();
    this.pendingConnections.clear();
    this.sourceIds = [];
  }
  /**
   * Get a connector by source ID
   * If sourceId is not provided, returns the default (first) connector
   */
  getConnector(sourceId) {
    const id = sourceId || this.sourceIds[0];
    const connector = this.connectors.get(id);
    if (!connector) {
      if (sourceId) {
        throw new Error(
          `Source '${sourceId}' not found. Available sources: ${this.sourceIds.join(", ")}`
        );
      } else {
        throw new Error("No sources connected. Call connectWithSources() first.");
      }
    }
    return connector;
  }
  /**
   * Get all available connector types
   */
  static getAvailableConnectors() {
    return ConnectorRegistry.getAvailableConnectors();
  }
  /**
   * Get sample DSNs for all available connectors
   */
  static getAllSampleDSNs() {
    return ConnectorRegistry.getAllSampleDSNs();
  }
  /**
   * Get the current active connector instance
   * This is used by resource and tool handlers
   * @param sourceId - Optional source ID. If not provided, returns default (first) connector
   */
  static getCurrentConnector(sourceId) {
    if (!managerInstance) {
      throw new Error("ConnectorManager not initialized");
    }
    return managerInstance.getConnector(sourceId);
  }
  /**
   * Get all available source IDs
   */
  getSourceIds() {
    return [...this.sourceIds];
  }
  /** Get all available source IDs */
  static getAvailableSourceIds() {
    if (!managerInstance) {
      throw new Error("ConnectorManager not initialized");
    }
    return managerInstance.getSourceIds();
  }
  /**
   * Get source configuration by ID
   * @param sourceId - Source ID. If not provided, returns default (first) source config
   */
  getSourceConfig(sourceId) {
    if (this.sourceIds.length === 0) {
      return null;
    }
    const id = sourceId || this.sourceIds[0];
    return this.sourceConfigs.get(id) || null;
  }
  /**
   * Get all source configurations
   */
  getAllSourceConfigs() {
    return this.sourceIds.map((id) => this.sourceConfigs.get(id));
  }
  /**
   * Get source configuration by ID (static method for external access)
   */
  static getSourceConfig(sourceId) {
    if (!managerInstance) {
      throw new Error("ConnectorManager not initialized");
    }
    return managerInstance.getSourceConfig(sourceId);
  }
  /**
   * Get all source configurations (static method for external access)
   */
  static getAllSourceConfigs() {
    if (!managerInstance) {
      throw new Error("ConnectorManager not initialized");
    }
    return managerInstance.getAllSourceConfigs();
  }
  /**
   * Get default port for a database based on DSN protocol
   */
  getDefaultPort(dsn) {
    const type = getDatabaseTypeFromDSN(dsn);
    if (!type) {
      return 0;
    }
    return getDefaultPortForType(type) ?? 0;
  }
};

// src/utils/sql-parser.ts
function stripCommentsAndStrings(sql) {
  let result = "";
  let i = 0;
  while (i < sql.length) {
    if (sql[i] === "-" && sql[i + 1] === "-") {
      while (i < sql.length && sql[i] !== "\n") {
        i++;
      }
      result += " ";
      continue;
    }
    if (sql[i] === "/" && sql[i + 1] === "*") {
      i += 2;
      while (i < sql.length && !(sql[i] === "*" && sql[i + 1] === "/")) {
        i++;
      }
      i += 2;
      result += " ";
      continue;
    }
    if (sql[i] === "'") {
      i++;
      while (i < sql.length) {
        if (sql[i] === "'" && sql[i + 1] === "'") {
          i += 2;
        } else if (sql[i] === "'") {
          i++;
          break;
        } else {
          i++;
        }
      }
      result += " ";
      continue;
    }
    if (sql[i] === '"') {
      i++;
      while (i < sql.length) {
        if (sql[i] === '"' && sql[i + 1] === '"') {
          i += 2;
        } else if (sql[i] === '"') {
          i++;
          break;
        } else {
          i++;
        }
      }
      result += " ";
      continue;
    }
    result += sql[i];
    i++;
  }
  return result;
}

// src/utils/parameter-mapper.ts
var PARAMETER_STYLES = {
  postgres: "numbered",
  // $1, $2, $3
  mysql: "positional",
  // ?, ?, ?
  mariadb: "positional",
  // ?, ?, ?
  sqlserver: "named",
  // @p1, @p2, @p3
  sqlite: "positional"
  // ?, ?, ?
};
function detectParameterStyle(statement) {
  const cleanedSQL = stripCommentsAndStrings(statement);
  if (/\$\d+/.test(cleanedSQL)) {
    return "numbered";
  }
  if (/@p\d+/.test(cleanedSQL)) {
    return "named";
  }
  if (/\?/.test(cleanedSQL)) {
    return "positional";
  }
  return "none";
}
function validateParameterStyle(statement, connectorType) {
  const detectedStyle = detectParameterStyle(statement);
  const expectedStyle = PARAMETER_STYLES[connectorType];
  if (detectedStyle === "none") {
    return;
  }
  if (detectedStyle !== expectedStyle) {
    const examples = {
      numbered: "$1, $2, $3",
      positional: "?, ?, ?",
      named: "@p1, @p2, @p3"
    };
    throw new Error(
      `Invalid parameter syntax for ${connectorType}. Expected ${expectedStyle} style (${examples[expectedStyle]}), but found ${detectedStyle} style in statement.`
    );
  }
}
function countParameters(statement) {
  const style = detectParameterStyle(statement);
  const cleanedSQL = stripCommentsAndStrings(statement);
  switch (style) {
    case "numbered": {
      const matches = cleanedSQL.match(/\$\d+/g);
      if (!matches) return 0;
      const numbers = matches.map((m) => parseInt(m.slice(1), 10));
      const uniqueIndices = Array.from(new Set(numbers)).sort((a, b) => a - b);
      const maxIndex = Math.max(...uniqueIndices);
      for (let i = 1; i <= maxIndex; i++) {
        if (!uniqueIndices.includes(i)) {
          throw new Error(
            `Non-sequential numbered parameters detected. Found placeholders: ${uniqueIndices.map((n) => `$${n}`).join(", ")}. Parameters must be sequential starting from $1 (missing $${i}).`
          );
        }
      }
      return maxIndex;
    }
    case "named": {
      const matches = cleanedSQL.match(/@p\d+/g);
      if (!matches) return 0;
      const numbers = matches.map((m) => parseInt(m.slice(2), 10));
      const uniqueIndices = Array.from(new Set(numbers)).sort((a, b) => a - b);
      const maxIndex = Math.max(...uniqueIndices);
      for (let i = 1; i <= maxIndex; i++) {
        if (!uniqueIndices.includes(i)) {
          throw new Error(
            `Non-sequential named parameters detected. Found placeholders: ${uniqueIndices.map((n) => `@p${n}`).join(", ")}. Parameters must be sequential starting from @p1 (missing @p${i}).`
          );
        }
      }
      return maxIndex;
    }
    case "positional": {
      return (cleanedSQL.match(/\?/g) || []).length;
    }
    default:
      return 0;
  }
}
function validateParameters(statement, parameters, connectorType) {
  validateParameterStyle(statement, connectorType);
  const paramCount = countParameters(statement);
  const definedCount = parameters?.length || 0;
  if (paramCount !== definedCount) {
    throw new Error(
      `Parameter count mismatch: SQL statement has ${paramCount} parameter(s), but ${definedCount} parameter(s) defined in tool configuration.`
    );
  }
}
function mapArgumentsToArray(parameters, args) {
  if (!parameters || parameters.length === 0) {
    return [];
  }
  return parameters.map((param) => {
    const value = args[param.name];
    if (value !== void 0) {
      return value;
    }
    if (param.default !== void 0) {
      return param.default;
    }
    if (param.required !== false) {
      throw new Error(
        `Required parameter '${param.name}' is missing and has no default value.`
      );
    }
    return null;
  });
}

// src/tools/registry.ts
var ToolRegistry = class {
  constructor(config) {
    this.toolsBySource = this.buildRegistry(config);
  }
  /**
   * Check if a tool name is a built-in tool
   */
  isBuiltinTool(toolName) {
    return BUILTIN_TOOLS.includes(toolName);
  }
  /**
   * Validate a custom tool parameter definition
   */
  validateParameter(toolName, param) {
    if (!param.name || param.name.trim() === "") {
      throw new Error(`Tool '${toolName}' has parameter missing 'name' field`);
    }
    if (!param.type) {
      throw new Error(
        `Tool '${toolName}', parameter '${param.name}' missing 'type' field`
      );
    }
    const validTypes = ["string", "integer", "float", "boolean", "array"];
    if (!validTypes.includes(param.type)) {
      throw new Error(
        `Tool '${toolName}', parameter '${param.name}' has invalid type '${param.type}'. Valid types: ${validTypes.join(", ")}`
      );
    }
    if (!param.description || param.description.trim() === "") {
      throw new Error(
        `Tool '${toolName}', parameter '${param.name}' missing 'description' field`
      );
    }
    if (param.allowed_values) {
      if (!Array.isArray(param.allowed_values)) {
        throw new Error(
          `Tool '${toolName}', parameter '${param.name}': allowed_values must be an array`
        );
      }
      if (param.allowed_values.length === 0) {
        throw new Error(
          `Tool '${toolName}', parameter '${param.name}': allowed_values cannot be empty`
        );
      }
    }
    if (param.default !== void 0 && param.allowed_values) {
      if (!param.allowed_values.includes(param.default)) {
        throw new Error(
          `Tool '${toolName}', parameter '${param.name}': default value '${param.default}' is not in allowed_values: ${param.allowed_values.join(", ")}`
        );
      }
    }
  }
  /**
   * Validate a custom tool configuration
   */
  validateCustomTool(toolConfig, availableSources) {
    if (!toolConfig.name || toolConfig.name.trim() === "") {
      throw new Error("Tool definition missing required field: name");
    }
    if (!toolConfig.description || toolConfig.description.trim() === "") {
      throw new Error(
        `Tool '${toolConfig.name}' missing required field: description`
      );
    }
    if (!toolConfig.source || toolConfig.source.trim() === "") {
      throw new Error(
        `Tool '${toolConfig.name}' missing required field: source`
      );
    }
    if (!toolConfig.statement || toolConfig.statement.trim() === "") {
      throw new Error(
        `Tool '${toolConfig.name}' missing required field: statement`
      );
    }
    if (!availableSources.includes(toolConfig.source)) {
      throw new Error(
        `Tool '${toolConfig.name}' references unknown source '${toolConfig.source}'. Available sources: ${availableSources.join(", ")}`
      );
    }
    for (const builtinName of BUILTIN_TOOLS) {
      if (toolConfig.name === builtinName || toolConfig.name.startsWith(`${builtinName}_`)) {
        throw new Error(
          `Tool name '${toolConfig.name}' conflicts with built-in tool naming pattern. Custom tools cannot use names starting with: ${BUILTIN_TOOLS.join(", ")}`
        );
      }
    }
    const sourceConfig = ConnectorManager.getSourceConfig(toolConfig.source);
    const connectorType = sourceConfig.type;
    try {
      validateParameters(
        toolConfig.statement,
        toolConfig.parameters,
        connectorType
      );
    } catch (error) {
      throw new Error(
        `Tool '${toolConfig.name}' validation failed: ${error.message}`
      );
    }
    if (toolConfig.parameters) {
      for (const param of toolConfig.parameters) {
        this.validateParameter(toolConfig.name, param);
      }
    }
  }
  /**
   * Build the internal registry mapping sources to their enabled tools
   */
  buildRegistry(config) {
    const registry = /* @__PURE__ */ new Map();
    const availableSources = config.sources.map((s) => s.id);
    const customToolNames = /* @__PURE__ */ new Set();
    for (const tool of config.tools || []) {
      if (!this.isBuiltinTool(tool.name)) {
        this.validateCustomTool(tool, availableSources);
        if (customToolNames.has(tool.name)) {
          throw new Error(
            `Duplicate tool name '${tool.name}'. Tool names must be unique.`
          );
        }
        customToolNames.add(tool.name);
      }
      const existing = registry.get(tool.source) || [];
      existing.push(tool);
      registry.set(tool.source, existing);
    }
    for (const source of config.sources) {
      if (!registry.has(source.id)) {
        const defaultTools = BUILTIN_TOOLS.map((name) => {
          if (name === "execute_sql") {
            return { name: "execute_sql", source: source.id };
          } else {
            return { name: "search_objects", source: source.id };
          }
        });
        registry.set(source.id, defaultTools);
      }
    }
    return registry;
  }
  /**
   * Get all enabled tool configs for a specific source
   */
  getEnabledToolConfigs(sourceId) {
    return this.toolsBySource.get(sourceId) || [];
  }
  /**
   * Get built-in tool configuration for a specific source
   * Returns undefined if tool is not enabled or not a built-in
   */
  getBuiltinToolConfig(toolName, sourceId) {
    if (!this.isBuiltinTool(toolName)) {
      return void 0;
    }
    const tools = this.getEnabledToolConfigs(sourceId);
    return tools.find((t) => t.name === toolName);
  }
  /**
   * Get all unique tools across all sources (for tools/list response)
   * Returns the union of all enabled tools
   */
  getAllTools() {
    const seen = /* @__PURE__ */ new Set();
    const result = [];
    for (const tools of this.toolsBySource.values()) {
      for (const tool of tools) {
        if (!seen.has(tool.name)) {
          seen.add(tool.name);
          result.push(tool);
        }
      }
    }
    return result;
  }
  /**
   * Get all custom tools (non-builtin) across all sources
   */
  getCustomTools() {
    return this.getAllTools().filter((tool) => !this.isBuiltinTool(tool.name));
  }
  /**
   * Get all built-in tool names that are enabled across any source
   */
  getEnabledBuiltinToolNames() {
    const enabledBuiltins = /* @__PURE__ */ new Set();
    for (const tools of this.toolsBySource.values()) {
      for (const tool of tools) {
        if (this.isBuiltinTool(tool.name)) {
          enabledBuiltins.add(tool.name);
        }
      }
    }
    return Array.from(enabledBuiltins);
  }
};
var globalRegistry = null;
function initializeToolRegistry(config) {
  globalRegistry = new ToolRegistry(config);
}
function getToolRegistry() {
  if (!globalRegistry) {
    throw new Error(
      "Tool registry not initialized. Call initializeToolRegistry first."
    );
  }
  return globalRegistry;
}

export {
  ConnectorRegistry,
  SafeURL,
  parseConnectionInfoFromDSN,
  obfuscateDSNPassword,
  getDatabaseTypeFromDSN,
  getDefaultPortForType,
  stripCommentsAndStrings,
  isDemoMode,
  resolveTransport,
  resolvePort,
  resolveSourceConfigs,
  BUILTIN_TOOL_EXECUTE_SQL,
  BUILTIN_TOOL_SEARCH_OBJECTS,
  ConnectorManager,
  mapArgumentsToArray,
  ToolRegistry,
  initializeToolRegistry,
  getToolRegistry
};
