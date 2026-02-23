#!/usr/bin/env node
import {
  BUILTIN_TOOL_EXECUTE_SQL,
  BUILTIN_TOOL_SEARCH_OBJECTS,
  ConnectorManager,
  ConnectorRegistry,
  SafeURL,
  getDatabaseTypeFromDSN,
  getDefaultPortForType,
  getToolRegistry,
  isDemoMode,
  mapArgumentsToArray,
  obfuscateDSNPassword,
  parseConnectionInfoFromDSN,
  resolvePort,
  resolveSourceConfigs,
  resolveTransport,
  stripCommentsAndStrings
} from "./chunk-BRQMBLES.js";

// src/connectors/postgres/index.ts
import pg from "pg";

// src/utils/sql-row-limiter.ts
var SQLRowLimiter = class {
  /**
   * Check if a SQL statement is a SELECT query that can benefit from row limiting
   * Only handles SELECT queries
   */
  static isSelectQuery(sql2) {
    const trimmed = sql2.trim().toLowerCase();
    return trimmed.startsWith("select");
  }
  /**
   * Check if a SQL statement already has a LIMIT clause.
   * Strips comments and string literals first to avoid false positives.
   */
  static hasLimitClause(sql2) {
    const cleanedSQL = stripCommentsAndStrings(sql2);
    const limitRegex = /\blimit\s+(?:\d+|\$\d+|\?|@p\d+)/i;
    return limitRegex.test(cleanedSQL);
  }
  /**
   * Check if a SQL statement already has a TOP clause (SQL Server).
   * Strips comments and string literals first to avoid false positives.
   */
  static hasTopClause(sql2) {
    const cleanedSQL = stripCommentsAndStrings(sql2);
    const topRegex = /\bselect\s+top\s+\d+/i;
    return topRegex.test(cleanedSQL);
  }
  /**
   * Extract existing LIMIT value from SQL if present.
   * Strips comments and string literals first to avoid false positives.
   */
  static extractLimitValue(sql2) {
    const cleanedSQL = stripCommentsAndStrings(sql2);
    const limitMatch = cleanedSQL.match(/\blimit\s+(\d+)/i);
    if (limitMatch) {
      return parseInt(limitMatch[1], 10);
    }
    return null;
  }
  /**
   * Extract existing TOP value from SQL if present (SQL Server).
   * Strips comments and string literals first to avoid false positives.
   */
  static extractTopValue(sql2) {
    const cleanedSQL = stripCommentsAndStrings(sql2);
    const topMatch = cleanedSQL.match(/\bselect\s+top\s+(\d+)/i);
    if (topMatch) {
      return parseInt(topMatch[1], 10);
    }
    return null;
  }
  /**
   * Add or modify LIMIT clause in a SQL statement
   */
  static applyLimitToQuery(sql2, maxRows) {
    const existingLimit = this.extractLimitValue(sql2);
    if (existingLimit !== null) {
      const effectiveLimit = Math.min(existingLimit, maxRows);
      return sql2.replace(/\blimit\s+\d+/i, `LIMIT ${effectiveLimit}`);
    } else {
      const trimmed = sql2.trim();
      const hasSemicolon = trimmed.endsWith(";");
      const sqlWithoutSemicolon = hasSemicolon ? trimmed.slice(0, -1) : trimmed;
      return `${sqlWithoutSemicolon} LIMIT ${maxRows}${hasSemicolon ? ";" : ""}`;
    }
  }
  /**
   * Add or modify TOP clause in a SQL statement (SQL Server)
   */
  static applyTopToQuery(sql2, maxRows) {
    const existingTop = this.extractTopValue(sql2);
    if (existingTop !== null) {
      const effectiveTop = Math.min(existingTop, maxRows);
      return sql2.replace(/\bselect\s+top\s+\d+/i, `SELECT TOP ${effectiveTop}`);
    } else {
      return sql2.replace(/\bselect\s+/i, `SELECT TOP ${maxRows} `);
    }
  }
  /**
   * Check if a LIMIT clause uses a parameter placeholder (not a literal number).
   * Strips comments and string literals first to avoid false positives.
   */
  static hasParameterizedLimit(sql2) {
    const cleanedSQL = stripCommentsAndStrings(sql2);
    const parameterizedLimitRegex = /\blimit\s+(?:\$\d+|\?|@p\d+)/i;
    return parameterizedLimitRegex.test(cleanedSQL);
  }
  /**
   * Apply maxRows limit to a SELECT query only
   *
   * This method is used by PostgreSQL, MySQL, MariaDB, and SQLite connectors which all support
   * the LIMIT clause syntax. SQL Server uses applyMaxRowsForSQLServer() instead with TOP syntax.
   *
   * For parameterized LIMIT clauses (e.g., LIMIT $1 or LIMIT ?), we wrap the query in a subquery
   * to enforce max_rows as a hard cap, since the parameter value is not known until runtime.
   */
  static applyMaxRows(sql2, maxRows) {
    if (!maxRows || !this.isSelectQuery(sql2)) {
      return sql2;
    }
    if (this.hasParameterizedLimit(sql2)) {
      const trimmed = sql2.trim();
      const hasSemicolon = trimmed.endsWith(";");
      const sqlWithoutSemicolon = hasSemicolon ? trimmed.slice(0, -1) : trimmed;
      return `SELECT * FROM (${sqlWithoutSemicolon}) AS subq LIMIT ${maxRows}${hasSemicolon ? ";" : ""}`;
    }
    return this.applyLimitToQuery(sql2, maxRows);
  }
  /**
   * Apply maxRows limit to a SELECT query using SQL Server TOP syntax
   */
  static applyMaxRowsForSQLServer(sql2, maxRows) {
    if (!maxRows || !this.isSelectQuery(sql2)) {
      return sql2;
    }
    return this.applyTopToQuery(sql2, maxRows);
  }
};

// src/utils/identifier-quoter.ts
function quoteIdentifier(identifier, dbType) {
  if (/[\0\x08\x09\x1a\n\r]/.test(identifier)) {
    throw new Error(`Invalid identifier: contains control characters: ${identifier}`);
  }
  if (!identifier) {
    throw new Error("Identifier cannot be empty");
  }
  switch (dbType) {
    case "postgres":
    case "sqlite":
      return `"${identifier.replace(/"/g, '""')}"`;
    case "mysql":
    case "mariadb":
      return `\`${identifier.replace(/`/g, "``")}\``;
    case "sqlserver":
      return `[${identifier.replace(/]/g, "]]")}]`;
    default:
      return `"${identifier.replace(/"/g, '""')}"`;
  }
}
function quoteQualifiedIdentifier(tableName, schemaName, dbType) {
  const quotedTable = quoteIdentifier(tableName, dbType);
  if (schemaName) {
    const quotedSchema = quoteIdentifier(schemaName, dbType);
    return `${quotedSchema}.${quotedTable}`;
  }
  return quotedTable;
}

// src/connectors/postgres/index.ts
var { Pool } = pg;
var PostgresDSNParser = class {
  async parse(dsn, config) {
    const connectionTimeoutSeconds = config?.connectionTimeoutSeconds;
    const queryTimeoutSeconds = config?.queryTimeoutSeconds;
    if (!this.isValidDSN(dsn)) {
      const obfuscatedDSN = obfuscateDSNPassword(dsn);
      const expectedFormat = this.getSampleDSN();
      throw new Error(
        `Invalid PostgreSQL DSN format.
Provided: ${obfuscatedDSN}
Expected: ${expectedFormat}`
      );
    }
    try {
      const url = new SafeURL(dsn);
      const poolConfig = {
        host: url.hostname,
        port: url.port ? parseInt(url.port) : 5432,
        database: url.pathname ? url.pathname.substring(1) : "",
        // Remove leading '/' if exists
        user: url.username,
        password: url.password
      };
      url.forEachSearchParam((value, key) => {
        if (key === "sslmode") {
          if (value === "disable") {
            poolConfig.ssl = false;
          } else if (value === "require") {
            poolConfig.ssl = { rejectUnauthorized: false };
          } else {
            poolConfig.ssl = true;
          }
        }
      });
      if (connectionTimeoutSeconds !== void 0) {
        poolConfig.connectionTimeoutMillis = connectionTimeoutSeconds * 1e3;
      }
      if (queryTimeoutSeconds !== void 0) {
        poolConfig.query_timeout = queryTimeoutSeconds * 1e3;
      }
      return poolConfig;
    } catch (error) {
      throw new Error(
        `Failed to parse PostgreSQL DSN: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
  getSampleDSN() {
    return "postgres://postgres:password@localhost:5432/postgres?sslmode=require";
  }
  isValidDSN(dsn) {
    try {
      return dsn.startsWith("postgres://") || dsn.startsWith("postgresql://");
    } catch (error) {
      return false;
    }
  }
};
var PostgresConnector = class _PostgresConnector {
  constructor() {
    this.id = "postgres";
    this.name = "PostgreSQL";
    this.dsnParser = new PostgresDSNParser();
    this.pool = null;
    // Source ID is set by ConnectorManager after cloning
    this.sourceId = "default";
    // Default schema for discovery methods (first entry from search_path, or "public")
    this.defaultSchema = "public";
  }
  getId() {
    return this.sourceId;
  }
  clone() {
    return new _PostgresConnector();
  }
  async connect(dsn, initScript, config) {
    this.defaultSchema = "public";
    try {
      const poolConfig = await this.dsnParser.parse(dsn, config);
      if (config?.readonly) {
        poolConfig.options = (poolConfig.options || "") + " -c default_transaction_read_only=on";
      }
      if (config?.searchPath) {
        const schemas = config.searchPath.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
        if (schemas.length > 0) {
          this.defaultSchema = schemas[0];
          const quotedSchemas = schemas.map((s) => quoteIdentifier(s, "postgres"));
          const optionsValue = quotedSchemas.join(",").replace(/\\/g, "\\\\").replace(/ /g, "\\ ");
          poolConfig.options = (poolConfig.options || "") + ` -c search_path=${optionsValue}`;
        }
      }
      this.pool = new Pool(poolConfig);
      const client = await this.pool.connect();
      client.release();
    } catch (err) {
      console.error("Failed to connect to PostgreSQL database:", err);
      throw err;
    }
  }
  async disconnect() {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
    }
  }
  async getSchemas() {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const client = await this.pool.connect();
    try {
      const result = await client.query(`
        SELECT schema_name
        FROM information_schema.schemata
        WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
        ORDER BY schema_name
      `);
      return result.rows.map((row) => row.schema_name);
    } finally {
      client.release();
    }
  }
  async getTables(schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const client = await this.pool.connect();
    try {
      const schemaToUse = schema || this.defaultSchema;
      const result = await client.query(
        `
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = $1
        ORDER BY table_name
      `,
        [schemaToUse]
      );
      return result.rows.map((row) => row.table_name);
    } finally {
      client.release();
    }
  }
  async tableExists(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const client = await this.pool.connect();
    try {
      const schemaToUse = schema || this.defaultSchema;
      const result = await client.query(
        `
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_schema = $1 
          AND table_name = $2
        )
      `,
        [schemaToUse, tableName]
      );
      return result.rows[0].exists;
    } finally {
      client.release();
    }
  }
  async getTableIndexes(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const client = await this.pool.connect();
    try {
      const schemaToUse = schema || this.defaultSchema;
      const result = await client.query(
        `
        SELECT 
          i.relname as index_name,
          array_agg(a.attname) as column_names,
          ix.indisunique as is_unique,
          ix.indisprimary as is_primary
        FROM 
          pg_class t,
          pg_class i,
          pg_index ix,
          pg_attribute a,
          pg_namespace ns
        WHERE 
          t.oid = ix.indrelid
          AND i.oid = ix.indexrelid
          AND a.attrelid = t.oid
          AND a.attnum = ANY(ix.indkey)
          AND t.relkind = 'r'
          AND t.relname = $1
          AND ns.oid = t.relnamespace
          AND ns.nspname = $2
        GROUP BY 
          i.relname, 
          ix.indisunique,
          ix.indisprimary
        ORDER BY 
          i.relname
      `,
        [tableName, schemaToUse]
      );
      return result.rows.map((row) => ({
        index_name: row.index_name,
        column_names: row.column_names,
        is_unique: row.is_unique,
        is_primary: row.is_primary
      }));
    } finally {
      client.release();
    }
  }
  async getTableSchema(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const client = await this.pool.connect();
    try {
      const schemaToUse = schema || this.defaultSchema;
      const result = await client.query(
        `
        SELECT
          c.column_name,
          c.data_type,
          c.is_nullable,
          c.column_default,
          pgd.description
        FROM information_schema.columns c
        LEFT JOIN pg_catalog.pg_namespace nsp
          ON nsp.nspname = c.table_schema
        LEFT JOIN pg_catalog.pg_class cls
          ON cls.relnamespace = nsp.oid
          AND cls.relname = c.table_name
        LEFT JOIN pg_catalog.pg_description pgd
          ON pgd.objoid = cls.oid
          AND pgd.objsubid = c.ordinal_position
        WHERE c.table_schema = $1
        AND c.table_name = $2
        ORDER BY c.ordinal_position
      `,
        [schemaToUse, tableName]
      );
      return result.rows;
    } finally {
      client.release();
    }
  }
  async getTableRowCount(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const client = await this.pool.connect();
    try {
      const schemaToUse = schema || this.defaultSchema;
      const result = await client.query(
        `
        SELECT c.reltuples::bigint as count
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = $1
        AND n.nspname = $2
        AND c.relkind IN ('r','p','m','f')
      `,
        [tableName, schemaToUse]
      );
      if (result.rows.length > 0) {
        const count = Number(result.rows[0].count);
        return count >= 0 ? count : null;
      }
      return null;
    } finally {
      client.release();
    }
  }
  async getTableComment(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const client = await this.pool.connect();
    try {
      const schemaToUse = schema || this.defaultSchema;
      const result = await client.query(
        `
        SELECT obj_description(c.oid) as table_comment
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = $1
        AND n.nspname = $2
        AND c.relkind IN ('r','p','m','f')
      `,
        [tableName, schemaToUse]
      );
      if (result.rows.length > 0) {
        return result.rows[0].table_comment || null;
      }
      return null;
    } finally {
      client.release();
    }
  }
  async getStoredProcedures(schema, routineType) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const client = await this.pool.connect();
    try {
      const schemaToUse = schema || this.defaultSchema;
      const params = [schemaToUse];
      let typeFilter = "";
      if (routineType === "function") {
        typeFilter = " AND routine_type = 'FUNCTION'";
      } else if (routineType === "procedure") {
        typeFilter = " AND routine_type = 'PROCEDURE'";
      }
      const result = await client.query(
        `
        SELECT
          routine_name
        FROM information_schema.routines
        WHERE routine_schema = $1${typeFilter}
        ORDER BY routine_name
      `,
        params
      );
      return result.rows.map((row) => row.routine_name);
    } finally {
      client.release();
    }
  }
  async getStoredProcedureDetail(procedureName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const client = await this.pool.connect();
    try {
      const schemaToUse = schema || this.defaultSchema;
      const result = await client.query(
        `
        SELECT 
          routine_name as procedure_name,
          routine_type,
          CASE WHEN routine_type = 'PROCEDURE' THEN 'procedure' ELSE 'function' END as procedure_type,
          external_language as language,
          data_type as return_type,
          routine_definition as definition,
          (
            SELECT string_agg(
              parameter_name || ' ' || 
              parameter_mode || ' ' || 
              data_type,
              ', '
            )
            FROM information_schema.parameters
            WHERE specific_schema = $1
            AND specific_name = $2
            AND parameter_name IS NOT NULL
          ) as parameter_list
        FROM information_schema.routines
        WHERE routine_schema = $1
        AND routine_name = $2
      `,
        [schemaToUse, procedureName]
      );
      if (result.rows.length === 0) {
        throw new Error(`Stored procedure '${procedureName}' not found in schema '${schemaToUse}'`);
      }
      const procedure = result.rows[0];
      let definition = procedure.definition;
      try {
        const oidResult = await client.query(
          `
          SELECT p.oid, p.prosrc
          FROM pg_proc p
          JOIN pg_namespace n ON p.pronamespace = n.oid
          WHERE p.proname = $1
          AND n.nspname = $2
        `,
          [procedureName, schemaToUse]
        );
        if (oidResult.rows.length > 0) {
          if (!definition) {
            const oid = oidResult.rows[0].oid;
            const defResult = await client.query(`SELECT pg_get_functiondef($1)`, [oid]);
            if (defResult.rows.length > 0) {
              definition = defResult.rows[0].pg_get_functiondef;
            } else {
              definition = oidResult.rows[0].prosrc;
            }
          }
        }
      } catch (err) {
        console.error(`Error getting procedure definition: ${err}`);
      }
      return {
        procedure_name: procedure.procedure_name,
        procedure_type: procedure.procedure_type,
        language: procedure.language || "sql",
        parameter_list: procedure.parameter_list || "",
        return_type: procedure.return_type !== "void" ? procedure.return_type : void 0,
        definition: definition || void 0
      };
    } finally {
      client.release();
    }
  }
  async executeSQL(sql2, options, parameters) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const client = await this.pool.connect();
    try {
      const statements = sql2.split(";").map((statement) => statement.trim()).filter((statement) => statement.length > 0);
      if (statements.length === 1) {
        const processedStatement = SQLRowLimiter.applyMaxRows(statements[0], options.maxRows);
        let result;
        if (parameters && parameters.length > 0) {
          try {
            result = await client.query(processedStatement, parameters);
          } catch (error) {
            console.error(`[PostgreSQL executeSQL] ERROR: ${error.message}`);
            console.error(`[PostgreSQL executeSQL] SQL: ${processedStatement}`);
            console.error(`[PostgreSQL executeSQL] Parameters: ${JSON.stringify(parameters)}`);
            throw error;
          }
        } else {
          result = await client.query(processedStatement);
        }
        return { rows: result.rows, rowCount: result.rowCount ?? result.rows.length };
      } else {
        if (parameters && parameters.length > 0) {
          throw new Error("Parameters are not supported for multi-statement queries in PostgreSQL");
        }
        let allRows = [];
        let totalRowCount = 0;
        await client.query("BEGIN");
        try {
          for (let statement of statements) {
            const processedStatement = SQLRowLimiter.applyMaxRows(statement, options.maxRows);
            const result = await client.query(processedStatement);
            if (result.rows && result.rows.length > 0) {
              allRows.push(...result.rows);
            }
            if (result.rowCount) {
              totalRowCount += result.rowCount;
            }
          }
          await client.query("COMMIT");
        } catch (error) {
          await client.query("ROLLBACK");
          throw error;
        }
        return { rows: allRows, rowCount: totalRowCount };
      }
    } finally {
      client.release();
    }
  }
};
var postgresConnector = new PostgresConnector();
ConnectorRegistry.register(postgresConnector);

// src/connectors/sqlserver/index.ts
import sql from "mssql";
import { DefaultAzureCredential } from "@azure/identity";
var SQLServerDSNParser = class {
  async parse(dsn, config) {
    const connectionTimeoutSeconds = config?.connectionTimeoutSeconds;
    const queryTimeoutSeconds = config?.queryTimeoutSeconds;
    if (!this.isValidDSN(dsn)) {
      const obfuscatedDSN = obfuscateDSNPassword(dsn);
      const expectedFormat = this.getSampleDSN();
      throw new Error(
        `Invalid SQL Server DSN format.
Provided: ${obfuscatedDSN}
Expected: ${expectedFormat}`
      );
    }
    try {
      const url = new SafeURL(dsn);
      const options = {};
      url.forEachSearchParam((value, key) => {
        if (key === "authentication") {
          options.authentication = value;
        } else if (key === "sslmode") {
          options.sslmode = value;
        } else if (key === "instanceName") {
          options.instanceName = value;
        } else if (key === "domain") {
          options.domain = value;
        }
      });
      if (options.authentication === "ntlm" && !options.domain) {
        throw new Error("NTLM authentication requires 'domain' parameter");
      }
      if (options.domain && options.authentication !== "ntlm") {
        throw new Error("Parameter 'domain' requires 'authentication=ntlm'");
      }
      if (options.sslmode) {
        if (options.sslmode === "disable") {
          options.encrypt = false;
          options.trustServerCertificate = false;
        } else if (options.sslmode === "require") {
          options.encrypt = true;
          options.trustServerCertificate = true;
        }
      }
      const config2 = {
        server: url.hostname,
        port: url.port ? parseInt(url.port) : 1433,
        // Default SQL Server port
        database: url.pathname ? url.pathname.substring(1) : "",
        // Remove leading slash
        options: {
          encrypt: options.encrypt ?? false,
          // Default to unencrypted for development
          trustServerCertificate: options.trustServerCertificate ?? false,
          ...connectionTimeoutSeconds !== void 0 && {
            connectTimeout: connectionTimeoutSeconds * 1e3
          },
          ...queryTimeoutSeconds !== void 0 && {
            requestTimeout: queryTimeoutSeconds * 1e3
          },
          instanceName: options.instanceName
          // Add named instance support
        }
      };
      switch (options.authentication) {
        case "azure-active-directory-access-token": {
          try {
            const credential = new DefaultAzureCredential();
            const token = await credential.getToken("https://database.windows.net/");
            config2.authentication = {
              type: "azure-active-directory-access-token",
              options: {
                token: token.token
              }
            };
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            throw new Error(`Failed to get Azure AD token: ${errorMessage}`);
          }
          break;
        }
        case "ntlm":
          config2.authentication = {
            type: "ntlm",
            options: {
              domain: options.domain,
              userName: url.username,
              password: url.password
            }
          };
          break;
        default:
          config2.user = url.username;
          config2.password = url.password;
          break;
      }
      return config2;
    } catch (error) {
      throw new Error(
        `Failed to parse SQL Server DSN: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
  getSampleDSN() {
    return "sqlserver://username:password@localhost:1433/database?sslmode=disable&instanceName=INSTANCE1";
  }
  isValidDSN(dsn) {
    try {
      return dsn.startsWith("sqlserver://");
    } catch (error) {
      return false;
    }
  }
};
var SQLServerConnector = class _SQLServerConnector {
  constructor() {
    this.id = "sqlserver";
    this.name = "SQL Server";
    this.dsnParser = new SQLServerDSNParser();
    // Source ID is set by ConnectorManager after cloning
    this.sourceId = "default";
  }
  getId() {
    return this.sourceId;
  }
  clone() {
    return new _SQLServerConnector();
  }
  async connect(dsn, initScript, config) {
    try {
      this.config = await this.dsnParser.parse(dsn, config);
      if (!this.config.options) {
        this.config.options = {};
      }
      this.connection = await new sql.ConnectionPool(this.config).connect();
    } catch (error) {
      throw error;
    }
  }
  async disconnect() {
    if (this.connection) {
      await this.connection.close();
      this.connection = void 0;
    }
  }
  async getSchemas() {
    if (!this.connection) {
      throw new Error("Not connected to SQL Server database");
    }
    try {
      const result = await this.connection.request().query(`
          SELECT SCHEMA_NAME
          FROM INFORMATION_SCHEMA.SCHEMATA
          ORDER BY SCHEMA_NAME
      `);
      return result.recordset.map((row) => row.SCHEMA_NAME);
    } catch (error) {
      throw new Error(`Failed to get schemas: ${error.message}`);
    }
  }
  async getTables(schema) {
    if (!this.connection) {
      throw new Error("Not connected to SQL Server database");
    }
    try {
      const schemaToUse = schema || "dbo";
      const request = this.connection.request().input("schema", sql.VarChar, schemaToUse);
      const query = `
          SELECT TABLE_NAME
          FROM INFORMATION_SCHEMA.TABLES
          WHERE TABLE_SCHEMA = @schema
          ORDER BY TABLE_NAME
      `;
      const result = await request.query(query);
      return result.recordset.map((row) => row.TABLE_NAME);
    } catch (error) {
      throw new Error(`Failed to get tables: ${error.message}`);
    }
  }
  async tableExists(tableName, schema) {
    if (!this.connection) {
      throw new Error("Not connected to SQL Server database");
    }
    try {
      const schemaToUse = schema || "dbo";
      const request = this.connection.request().input("tableName", sql.VarChar, tableName).input("schema", sql.VarChar, schemaToUse);
      const query = `
          SELECT COUNT(*) as count
          FROM INFORMATION_SCHEMA.TABLES
          WHERE TABLE_NAME = @tableName
            AND TABLE_SCHEMA = @schema
      `;
      const result = await request.query(query);
      return result.recordset[0].count > 0;
    } catch (error) {
      throw new Error(`Failed to check if table exists: ${error.message}`);
    }
  }
  async getTableIndexes(tableName, schema) {
    if (!this.connection) {
      throw new Error("Not connected to SQL Server database");
    }
    try {
      const schemaToUse = schema || "dbo";
      const request = this.connection.request().input("tableName", sql.VarChar, tableName).input("schema", sql.VarChar, schemaToUse);
      const query = `
          SELECT i.name AS index_name,
                 i.is_unique,
                 i.is_primary_key,
                 c.name AS column_name,
                 ic.key_ordinal
          FROM sys.indexes i
                   INNER JOIN
               sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
                   INNER JOIN
               sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
                   INNER JOIN
               sys.tables t ON i.object_id = t.object_id
                   INNER JOIN
               sys.schemas s ON t.schema_id = s.schema_id
          WHERE t.name = @tableName
            AND s.name = @schema
          ORDER BY i.name,
                   ic.key_ordinal
      `;
      const result = await request.query(query);
      const indexMap = /* @__PURE__ */ new Map();
      for (const row of result.recordset) {
        const indexName = row.index_name;
        const columnName = row.column_name;
        const isUnique = !!row.is_unique;
        const isPrimary = !!row.is_primary_key;
        if (!indexMap.has(indexName)) {
          indexMap.set(indexName, {
            columns: [],
            is_unique: isUnique,
            is_primary: isPrimary
          });
        }
        const indexInfo = indexMap.get(indexName);
        indexInfo.columns.push(columnName);
      }
      const indexes = [];
      indexMap.forEach((info, name) => {
        indexes.push({
          index_name: name,
          column_names: info.columns,
          is_unique: info.is_unique,
          is_primary: info.is_primary
        });
      });
      return indexes;
    } catch (error) {
      throw new Error(`Failed to get indexes for table ${tableName}: ${error.message}`);
    }
  }
  async getTableSchema(tableName, schema) {
    if (!this.connection) {
      throw new Error("Not connected to SQL Server database");
    }
    try {
      const schemaToUse = schema || "dbo";
      const request = this.connection.request().input("tableName", sql.VarChar, tableName).input("schema", sql.VarChar, schemaToUse);
      const query = `
          SELECT c.COLUMN_NAME as    column_name,
                 c.DATA_TYPE as      data_type,
                 c.IS_NULLABLE as    is_nullable,
                 c.COLUMN_DEFAULT as column_default,
                 ep.value as         description
          FROM INFORMATION_SCHEMA.COLUMNS c
          LEFT JOIN sys.columns sc
            ON sc.name = c.COLUMN_NAME
            AND sc.object_id = OBJECT_ID(QUOTENAME(c.TABLE_SCHEMA) + '.' + QUOTENAME(c.TABLE_NAME))
          LEFT JOIN sys.extended_properties ep
            ON ep.major_id = sc.object_id
            AND ep.minor_id = sc.column_id
            AND ep.name = 'MS_Description'
          WHERE c.TABLE_NAME = @tableName
            AND c.TABLE_SCHEMA = @schema
          ORDER BY c.ORDINAL_POSITION
      `;
      const result = await request.query(query);
      return result.recordset.map((row) => ({
        ...row,
        description: row.description || null
      }));
    } catch (error) {
      throw new Error(`Failed to get schema for table ${tableName}: ${error.message}`);
    }
  }
  async getTableComment(tableName, schema) {
    if (!this.connection) {
      throw new Error("Not connected to SQL Server database");
    }
    try {
      const schemaToUse = schema || "dbo";
      const request = this.connection.request().input("tableName", sql.VarChar, tableName).input("schema", sql.VarChar, schemaToUse);
      const query = `
          SELECT ep.value as table_comment
          FROM sys.extended_properties ep
          JOIN sys.tables t ON ep.major_id = t.object_id
          JOIN sys.schemas s ON t.schema_id = s.schema_id
          WHERE ep.minor_id = 0
            AND ep.name = 'MS_Description'
            AND t.name = @tableName
            AND s.name = @schema
      `;
      const result = await request.query(query);
      if (result.recordset.length > 0) {
        return result.recordset[0].table_comment || null;
      }
      return null;
    } catch (error) {
      return null;
    }
  }
  async getStoredProcedures(schema, routineType) {
    if (!this.connection) {
      throw new Error("Not connected to SQL Server database");
    }
    try {
      const schemaToUse = schema || "dbo";
      const request = this.connection.request().input("schema", sql.VarChar, schemaToUse);
      let typeFilter;
      if (routineType === "function") {
        typeFilter = "AND ROUTINE_TYPE = 'FUNCTION'";
      } else if (routineType === "procedure") {
        typeFilter = "AND ROUTINE_TYPE = 'PROCEDURE'";
      } else {
        typeFilter = "AND (ROUTINE_TYPE = 'PROCEDURE' OR ROUTINE_TYPE = 'FUNCTION')";
      }
      const query = `
          SELECT ROUTINE_NAME
          FROM INFORMATION_SCHEMA.ROUTINES
          WHERE ROUTINE_SCHEMA = @schema
            ${typeFilter}
          ORDER BY ROUTINE_NAME
      `;
      const result = await request.query(query);
      return result.recordset.map((row) => row.ROUTINE_NAME);
    } catch (error) {
      throw new Error(`Failed to get stored procedures: ${error.message}`);
    }
  }
  async getStoredProcedureDetail(procedureName, schema) {
    if (!this.connection) {
      throw new Error("Not connected to SQL Server database");
    }
    try {
      const schemaToUse = schema || "dbo";
      const request = this.connection.request().input("procedureName", sql.VarChar, procedureName).input("schema", sql.VarChar, schemaToUse);
      const routineQuery = `
          SELECT ROUTINE_NAME as procedure_name,
                 ROUTINE_TYPE,
                 DATA_TYPE    as return_data_type
          FROM INFORMATION_SCHEMA.ROUTINES
          WHERE ROUTINE_NAME = @procedureName
            AND ROUTINE_SCHEMA = @schema
      `;
      const routineResult = await request.query(routineQuery);
      if (routineResult.recordset.length === 0) {
        throw new Error(`Stored procedure '${procedureName}' not found in schema '${schemaToUse}'`);
      }
      const routine = routineResult.recordset[0];
      const parameterQuery = `
          SELECT PARAMETER_NAME,
                 PARAMETER_MODE,
                 DATA_TYPE,
                 CHARACTER_MAXIMUM_LENGTH,
                 ORDINAL_POSITION
          FROM INFORMATION_SCHEMA.PARAMETERS
          WHERE SPECIFIC_NAME = @procedureName
            AND SPECIFIC_SCHEMA = @schema
          ORDER BY ORDINAL_POSITION
      `;
      const parameterResult = await request.query(parameterQuery);
      let parameterList = "";
      if (parameterResult.recordset.length > 0) {
        parameterList = parameterResult.recordset.map(
          (param) => {
            const lengthStr = param.CHARACTER_MAXIMUM_LENGTH > 0 ? `(${param.CHARACTER_MAXIMUM_LENGTH})` : "";
            return `${param.PARAMETER_NAME} ${param.PARAMETER_MODE} ${param.DATA_TYPE}${lengthStr}`;
          }
        ).join(", ");
      }
      const definitionQuery = `
          SELECT definition
          FROM sys.sql_modules sm
                   JOIN sys.objects o ON sm.object_id = o.object_id
                   JOIN sys.schemas s ON o.schema_id = s.schema_id
          WHERE o.name = @procedureName
            AND s.name = @schema
      `;
      const definitionResult = await request.query(definitionQuery);
      let definition = void 0;
      if (definitionResult.recordset.length > 0) {
        definition = definitionResult.recordset[0].definition;
      }
      return {
        procedure_name: routine.procedure_name,
        procedure_type: routine.ROUTINE_TYPE === "PROCEDURE" ? "procedure" : "function",
        language: "sql",
        // SQL Server procedures are typically in T-SQL
        parameter_list: parameterList,
        return_type: routine.ROUTINE_TYPE === "FUNCTION" ? routine.return_data_type : void 0,
        definition
      };
    } catch (error) {
      throw new Error(`Failed to get stored procedure details: ${error.message}`);
    }
  }
  async executeSQL(sqlQuery, options, parameters) {
    if (!this.connection) {
      throw new Error("Not connected to SQL Server database");
    }
    try {
      let processedSQL = sqlQuery;
      if (options.maxRows) {
        processedSQL = SQLRowLimiter.applyMaxRowsForSQLServer(sqlQuery, options.maxRows);
      }
      const request = this.connection.request();
      if (parameters && parameters.length > 0) {
        parameters.forEach((param, index) => {
          const paramName = `p${index + 1}`;
          if (typeof param === "string") {
            request.input(paramName, sql.VarChar, param);
          } else if (typeof param === "number") {
            if (Number.isInteger(param)) {
              request.input(paramName, sql.Int, param);
            } else {
              request.input(paramName, sql.Float, param);
            }
          } else if (typeof param === "boolean") {
            request.input(paramName, sql.Bit, param);
          } else if (param === null || param === void 0) {
            request.input(paramName, sql.VarChar, param);
          } else if (Array.isArray(param)) {
            request.input(paramName, sql.VarChar, JSON.stringify(param));
          } else {
            request.input(paramName, sql.VarChar, JSON.stringify(param));
          }
        });
      }
      let result;
      try {
        result = await request.query(processedSQL);
      } catch (error) {
        if (parameters && parameters.length > 0) {
          console.error(`[SQL Server executeSQL] ERROR: ${error.message}`);
          console.error(`[SQL Server executeSQL] SQL: ${processedSQL}`);
          console.error(`[SQL Server executeSQL] Parameters: ${JSON.stringify(parameters)}`);
        }
        throw error;
      }
      return {
        rows: result.recordset || [],
        rowCount: result.rowsAffected[0] || 0
      };
    } catch (error) {
      throw new Error(`Failed to execute query: ${error.message}`);
    }
  }
};
var sqlServerConnector = new SQLServerConnector();
ConnectorRegistry.register(sqlServerConnector);

// src/connectors/sqlite/index.ts
import Database from "better-sqlite3";
var SQLiteDSNParser = class {
  async parse(dsn, config) {
    if (!this.isValidDSN(dsn)) {
      const obfuscatedDSN = obfuscateDSNPassword(dsn);
      const expectedFormat = this.getSampleDSN();
      throw new Error(
        `Invalid SQLite DSN format.
Provided: ${obfuscatedDSN}
Expected: ${expectedFormat}`
      );
    }
    try {
      const url = new SafeURL(dsn);
      let dbPath;
      if (url.hostname === "" && url.pathname === "/:memory:") {
        dbPath = ":memory:";
      } else {
        if (url.pathname.startsWith("//")) {
          dbPath = url.pathname.substring(2);
        } else if (url.pathname.match(/^\/[A-Za-z]:\//)) {
          dbPath = url.pathname.substring(1);
        } else {
          dbPath = url.pathname;
        }
      }
      return { dbPath };
    } catch (error) {
      throw new Error(
        `Failed to parse SQLite DSN: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
  getSampleDSN() {
    return "sqlite:///path/to/database.db";
  }
  isValidDSN(dsn) {
    try {
      return dsn.startsWith("sqlite://");
    } catch (error) {
      return false;
    }
  }
};
var SQLiteConnector = class _SQLiteConnector {
  constructor() {
    this.id = "sqlite";
    this.name = "SQLite";
    this.dsnParser = new SQLiteDSNParser();
    this.db = null;
    this.dbPath = ":memory:";
    // Default to in-memory database
    // Source ID is set by ConnectorManager after cloning
    this.sourceId = "default";
  }
  getId() {
    return this.sourceId;
  }
  clone() {
    return new _SQLiteConnector();
  }
  /**
   * Connect to SQLite database
   * Note: SQLite does not support connection timeouts as it's a local file-based database.
   * The config parameter is accepted for interface compliance but ignored.
   */
  async connect(dsn, initScript, config) {
    const parsedConfig = await this.dsnParser.parse(dsn, config);
    this.dbPath = parsedConfig.dbPath;
    try {
      const dbOptions = {};
      if (config?.readonly && this.dbPath !== ":memory:") {
        dbOptions.readonly = true;
      }
      this.db = new Database(this.dbPath, dbOptions);
      if (initScript) {
        this.db.exec(initScript);
      }
    } catch (error) {
      console.error("Failed to connect to SQLite database:", error);
      throw error;
    }
  }
  async disconnect() {
    if (this.db) {
      try {
        if (!this.db.inTransaction) {
          this.db.close();
        } else {
          try {
            this.db.exec("ROLLBACK");
          } catch (rollbackError) {
          }
          this.db.close();
        }
        this.db = null;
      } catch (error) {
        console.error("Error during SQLite disconnect:", error);
        this.db = null;
      }
    }
    return Promise.resolve();
  }
  async getSchemas() {
    if (!this.db) {
      throw new Error("Not connected to SQLite database");
    }
    return ["main"];
  }
  async getTables(schema) {
    if (!this.db) {
      throw new Error("Not connected to SQLite database");
    }
    try {
      const rows = this.db.prepare(
        `
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name NOT LIKE 'sqlite_%'
        ORDER BY name
      `
      ).all();
      return rows.map((row) => row.name);
    } catch (error) {
      throw error;
    }
  }
  async tableExists(tableName, schema) {
    if (!this.db) {
      throw new Error("Not connected to SQLite database");
    }
    try {
      const row = this.db.prepare(
        `
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name = ?
      `
      ).get(tableName);
      return !!row;
    } catch (error) {
      throw error;
    }
  }
  async getTableIndexes(tableName, schema) {
    if (!this.db) {
      throw new Error("Not connected to SQLite database");
    }
    try {
      const indexInfoRows = this.db.prepare(
        `
        SELECT 
          name as index_name,
          0 as is_unique
        FROM sqlite_master 
        WHERE type = 'index' 
        AND tbl_name = ?
      `
      ).all(tableName);
      const quotedTableName = quoteIdentifier(tableName, "sqlite");
      const indexListRows = this.db.prepare(`PRAGMA index_list(${quotedTableName})`).all();
      const indexUniqueMap = /* @__PURE__ */ new Map();
      for (const indexListRow of indexListRows) {
        indexUniqueMap.set(indexListRow.name, indexListRow.unique === 1);
      }
      const tableInfo = this.db.prepare(`PRAGMA table_info(${quotedTableName})`).all();
      const pkColumns = tableInfo.filter((col) => col.pk > 0).map((col) => col.name);
      const results = [];
      for (const indexInfo of indexInfoRows) {
        const quotedIndexName = quoteIdentifier(indexInfo.index_name, "sqlite");
        const indexDetailRows = this.db.prepare(`PRAGMA index_info(${quotedIndexName})`).all();
        const columnNames = indexDetailRows.map((row) => row.name);
        results.push({
          index_name: indexInfo.index_name,
          column_names: columnNames,
          is_unique: indexUniqueMap.get(indexInfo.index_name) || false,
          is_primary: false
        });
      }
      if (pkColumns.length > 0) {
        results.push({
          index_name: "PRIMARY",
          column_names: pkColumns,
          is_unique: true,
          is_primary: true
        });
      }
      return results;
    } catch (error) {
      throw error;
    }
  }
  async getTableSchema(tableName, schema) {
    if (!this.db) {
      throw new Error("Not connected to SQLite database");
    }
    try {
      const quotedTableName = quoteIdentifier(tableName, "sqlite");
      const rows = this.db.prepare(`PRAGMA table_info(${quotedTableName})`).all();
      const columns = rows.map((row) => ({
        column_name: row.name,
        data_type: row.type,
        // In SQLite, primary key columns are automatically NOT NULL even if notnull=0
        is_nullable: row.notnull === 1 || row.pk > 0 ? "NO" : "YES",
        column_default: row.dflt_value,
        description: null
      }));
      return columns;
    } catch (error) {
      throw error;
    }
  }
  async getStoredProcedures(schema, routineType) {
    if (!this.db) {
      throw new Error("Not connected to SQLite database");
    }
    return [];
  }
  async getStoredProcedureDetail(procedureName, schema) {
    if (!this.db) {
      throw new Error("Not connected to SQLite database");
    }
    throw new Error(
      "SQLite does not support stored procedures. Functions are defined programmatically through the SQLite API, not stored in the database."
    );
  }
  async executeSQL(sql2, options, parameters) {
    if (!this.db) {
      throw new Error("Not connected to SQLite database");
    }
    try {
      const statements = sql2.split(";").map((statement) => statement.trim()).filter((statement) => statement.length > 0);
      if (statements.length === 1) {
        let processedStatement = statements[0];
        const trimmedStatement = statements[0].toLowerCase().trim();
        const isReadStatement = trimmedStatement.startsWith("select") || trimmedStatement.startsWith("with") || trimmedStatement.startsWith("explain") || trimmedStatement.startsWith("analyze") || trimmedStatement.startsWith("pragma") && (trimmedStatement.includes("table_info") || trimmedStatement.includes("index_info") || trimmedStatement.includes("index_list") || trimmedStatement.includes("foreign_key_list"));
        if (options.maxRows) {
          processedStatement = SQLRowLimiter.applyMaxRows(processedStatement, options.maxRows);
        }
        if (isReadStatement) {
          if (parameters && parameters.length > 0) {
            try {
              const rows = this.db.prepare(processedStatement).all(...parameters);
              return { rows, rowCount: rows.length };
            } catch (error) {
              console.error(`[SQLite executeSQL] ERROR: ${error.message}`);
              console.error(`[SQLite executeSQL] SQL: ${processedStatement}`);
              console.error(`[SQLite executeSQL] Parameters: ${JSON.stringify(parameters)}`);
              throw error;
            }
          } else {
            const rows = this.db.prepare(processedStatement).all();
            return { rows, rowCount: rows.length };
          }
        } else {
          let result;
          if (parameters && parameters.length > 0) {
            try {
              result = this.db.prepare(processedStatement).run(...parameters);
            } catch (error) {
              console.error(`[SQLite executeSQL] ERROR: ${error.message}`);
              console.error(`[SQLite executeSQL] SQL: ${processedStatement}`);
              console.error(`[SQLite executeSQL] Parameters: ${JSON.stringify(parameters)}`);
              throw error;
            }
          } else {
            result = this.db.prepare(processedStatement).run();
          }
          return { rows: [], rowCount: result.changes };
        }
      } else {
        if (parameters && parameters.length > 0) {
          throw new Error("Parameters are not supported for multi-statement queries in SQLite");
        }
        const readStatements = [];
        const writeStatements = [];
        for (const statement of statements) {
          const trimmedStatement = statement.toLowerCase().trim();
          if (trimmedStatement.startsWith("select") || trimmedStatement.startsWith("with") || trimmedStatement.startsWith("explain") || trimmedStatement.startsWith("analyze") || trimmedStatement.startsWith("pragma") && (trimmedStatement.includes("table_info") || trimmedStatement.includes("index_info") || trimmedStatement.includes("index_list") || trimmedStatement.includes("foreign_key_list"))) {
            readStatements.push(statement);
          } else {
            writeStatements.push(statement);
          }
        }
        let totalChanges = 0;
        for (const statement of writeStatements) {
          const result = this.db.prepare(statement).run();
          totalChanges += result.changes;
        }
        let allRows = [];
        for (let statement of readStatements) {
          statement = SQLRowLimiter.applyMaxRows(statement, options.maxRows);
          const result = this.db.prepare(statement).all();
          allRows.push(...result);
        }
        return { rows: allRows, rowCount: totalChanges + allRows.length };
      }
    } catch (error) {
      throw error;
    }
  }
};
var sqliteConnector = new SQLiteConnector();
ConnectorRegistry.register(sqliteConnector);

// src/connectors/mysql/index.ts
import mysql from "mysql2/promise";

// src/utils/multi-statement-result-parser.ts
function isMetadataObject(element) {
  if (!element || typeof element !== "object" || Array.isArray(element)) {
    return false;
  }
  return "affectedRows" in element || "insertId" in element || "fieldCount" in element || "warningStatus" in element;
}
function isMultiStatementResult(results) {
  if (!Array.isArray(results) || results.length === 0) {
    return false;
  }
  const firstElement = results[0];
  return isMetadataObject(firstElement) || Array.isArray(firstElement);
}
function extractRowsFromMultiStatement(results) {
  if (!Array.isArray(results)) {
    return [];
  }
  const allRows = [];
  for (const result of results) {
    if (Array.isArray(result)) {
      allRows.push(...result);
    }
  }
  return allRows;
}
function extractAffectedRows(results) {
  if (isMetadataObject(results)) {
    return results.affectedRows || 0;
  }
  if (!Array.isArray(results)) {
    return 0;
  }
  if (isMultiStatementResult(results)) {
    let totalAffected = 0;
    for (const result of results) {
      if (isMetadataObject(result)) {
        totalAffected += result.affectedRows || 0;
      } else if (Array.isArray(result)) {
        totalAffected += result.length;
      }
    }
    return totalAffected;
  }
  return results.length;
}
function parseQueryResults(results) {
  if (!Array.isArray(results)) {
    return [];
  }
  if (isMultiStatementResult(results)) {
    return extractRowsFromMultiStatement(results);
  }
  return results;
}

// src/connectors/mysql/index.ts
var MySQLDSNParser = class {
  async parse(dsn, config) {
    const connectionTimeoutSeconds = config?.connectionTimeoutSeconds;
    if (!this.isValidDSN(dsn)) {
      const obfuscatedDSN = obfuscateDSNPassword(dsn);
      const expectedFormat = this.getSampleDSN();
      throw new Error(
        `Invalid MySQL DSN format.
Provided: ${obfuscatedDSN}
Expected: ${expectedFormat}`
      );
    }
    try {
      const url = new SafeURL(dsn);
      const config2 = {
        host: url.hostname,
        port: url.port ? parseInt(url.port) : 3306,
        database: url.pathname ? url.pathname.substring(1) : "",
        // Remove leading '/' if exists
        user: url.username,
        password: url.password,
        multipleStatements: true
        // Enable native multi-statement support
      };
      url.forEachSearchParam((value, key) => {
        if (key === "sslmode") {
          if (value === "disable") {
            config2.ssl = void 0;
          } else if (value === "require") {
            config2.ssl = { rejectUnauthorized: false };
          } else {
            config2.ssl = {};
          }
        }
      });
      if (connectionTimeoutSeconds !== void 0) {
        config2.connectTimeout = connectionTimeoutSeconds * 1e3;
      }
      if (url.password && url.password.includes("X-Amz-Credential")) {
        config2.authPlugins = {
          mysql_clear_password: () => () => {
            return Buffer.from(url.password + "\0");
          }
        };
        if (config2.ssl === void 0) {
          config2.ssl = { rejectUnauthorized: false };
        }
      }
      return config2;
    } catch (error) {
      throw new Error(
        `Failed to parse MySQL DSN: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
  getSampleDSN() {
    return "mysql://root:password@localhost:3306/mysql?sslmode=require";
  }
  isValidDSN(dsn) {
    try {
      return dsn.startsWith("mysql://");
    } catch (error) {
      return false;
    }
  }
};
var MySQLConnector = class _MySQLConnector {
  constructor() {
    this.id = "mysql";
    this.name = "MySQL";
    this.dsnParser = new MySQLDSNParser();
    this.pool = null;
    // Source ID is set by ConnectorManager after cloning
    this.sourceId = "default";
  }
  getId() {
    return this.sourceId;
  }
  clone() {
    return new _MySQLConnector();
  }
  async connect(dsn, initScript, config) {
    try {
      const connectionOptions = await this.dsnParser.parse(dsn, config);
      this.pool = mysql.createPool(connectionOptions);
      if (config?.queryTimeoutSeconds !== void 0) {
        this.queryTimeoutMs = config.queryTimeoutSeconds * 1e3;
      }
      const [rows] = await this.pool.query("SELECT 1");
    } catch (err) {
      console.error("Failed to connect to MySQL database:", err);
      throw err;
    }
  }
  async disconnect() {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
    }
  }
  async getSchemas() {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const [rows] = await this.pool.query(`
        SELECT SCHEMA_NAME 
        FROM INFORMATION_SCHEMA.SCHEMATA
        ORDER BY SCHEMA_NAME
      `);
      return rows.map((row) => row.SCHEMA_NAME);
    } catch (error) {
      console.error("Error getting schemas:", error);
      throw error;
    }
  }
  async getTables(schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE TABLE_SCHEMA = ?" : "WHERE TABLE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema] : [];
      const [rows] = await this.pool.query(
        `
        SELECT TABLE_NAME 
        FROM INFORMATION_SCHEMA.TABLES 
        ${schemaClause}
        ORDER BY TABLE_NAME
      `,
        queryParams
      );
      return rows.map((row) => row.TABLE_NAME);
    } catch (error) {
      console.error("Error getting tables:", error);
      throw error;
    }
  }
  async tableExists(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE TABLE_SCHEMA = ?" : "WHERE TABLE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema, tableName] : [tableName];
      const [rows] = await this.pool.query(
        `
        SELECT COUNT(*) AS COUNT
        FROM INFORMATION_SCHEMA.TABLES 
        ${schemaClause} 
        AND TABLE_NAME = ?
      `,
        queryParams
      );
      return rows[0].COUNT > 0;
    } catch (error) {
      console.error("Error checking if table exists:", error);
      throw error;
    }
  }
  async getTableIndexes(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "TABLE_SCHEMA = ?" : "TABLE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema, tableName] : [tableName];
      const [indexRows] = await this.pool.query(
        `
        SELECT 
          INDEX_NAME,
          COLUMN_NAME,
          NON_UNIQUE,
          SEQ_IN_INDEX
        FROM 
          INFORMATION_SCHEMA.STATISTICS 
        WHERE 
          ${schemaClause}
          AND TABLE_NAME = ? 
        ORDER BY 
          INDEX_NAME, 
          SEQ_IN_INDEX
      `,
        queryParams
      );
      const indexMap = /* @__PURE__ */ new Map();
      for (const row of indexRows) {
        const indexName = row.INDEX_NAME;
        const columnName = row.COLUMN_NAME;
        const isUnique = row.NON_UNIQUE === 0;
        const isPrimary = indexName === "PRIMARY";
        if (!indexMap.has(indexName)) {
          indexMap.set(indexName, {
            columns: [],
            is_unique: isUnique,
            is_primary: isPrimary
          });
        }
        const indexInfo = indexMap.get(indexName);
        indexInfo.columns.push(columnName);
      }
      const results = [];
      indexMap.forEach((indexInfo, indexName) => {
        results.push({
          index_name: indexName,
          column_names: indexInfo.columns,
          is_unique: indexInfo.is_unique,
          is_primary: indexInfo.is_primary
        });
      });
      return results;
    } catch (error) {
      console.error("Error getting table indexes:", error);
      throw error;
    }
  }
  async getTableSchema(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE TABLE_SCHEMA = ?" : "WHERE TABLE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema, tableName] : [tableName];
      const [rows] = await this.pool.query(
        `
        SELECT
          COLUMN_NAME as column_name,
          DATA_TYPE as data_type,
          IS_NULLABLE as is_nullable,
          COLUMN_DEFAULT as column_default,
          COLUMN_COMMENT as description
        FROM INFORMATION_SCHEMA.COLUMNS
        ${schemaClause}
        AND TABLE_NAME = ?
        ORDER BY ORDINAL_POSITION
      `,
        queryParams
      );
      return rows.map((row) => ({
        ...row,
        description: row.description || null
      }));
    } catch (error) {
      console.error("Error getting table schema:", error);
      throw error;
    }
  }
  async getTableComment(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE TABLE_SCHEMA = ?" : "WHERE TABLE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema, tableName] : [tableName];
      const [rows] = await this.pool.query(
        `
        SELECT TABLE_COMMENT
        FROM INFORMATION_SCHEMA.TABLES
        ${schemaClause}
        AND TABLE_NAME = ?
      `,
        queryParams
      );
      if (rows.length > 0) {
        return rows[0].TABLE_COMMENT || null;
      }
      return null;
    } catch (error) {
      return null;
    }
  }
  async getStoredProcedures(schema, routineType) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE ROUTINE_SCHEMA = ?" : "WHERE ROUTINE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema] : [];
      let typeFilter = "";
      if (routineType === "function") {
        typeFilter = " AND ROUTINE_TYPE = 'FUNCTION'";
      } else if (routineType === "procedure") {
        typeFilter = " AND ROUTINE_TYPE = 'PROCEDURE'";
      }
      const [rows] = await this.pool.query(
        `
        SELECT ROUTINE_NAME
        FROM INFORMATION_SCHEMA.ROUTINES
        ${schemaClause}${typeFilter}
        ORDER BY ROUTINE_NAME
      `,
        queryParams
      );
      return rows.map((row) => row.ROUTINE_NAME);
    } catch (error) {
      console.error("Error getting stored procedures:", error);
      throw error;
    }
  }
  async getStoredProcedureDetail(procedureName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE r.ROUTINE_SCHEMA = ?" : "WHERE r.ROUTINE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema, procedureName] : [procedureName];
      const [rows] = await this.pool.query(
        `
        SELECT 
          r.ROUTINE_NAME AS procedure_name,
          CASE 
            WHEN r.ROUTINE_TYPE = 'PROCEDURE' THEN 'procedure'
            ELSE 'function'
          END AS procedure_type,
          LOWER(r.ROUTINE_TYPE) AS routine_type,
          r.ROUTINE_DEFINITION,
          r.DTD_IDENTIFIER AS return_type,
          (
            SELECT GROUP_CONCAT(
              CONCAT(p.PARAMETER_NAME, ' ', p.PARAMETER_MODE, ' ', p.DATA_TYPE)
              ORDER BY p.ORDINAL_POSITION
              SEPARATOR ', '
            )
            FROM INFORMATION_SCHEMA.PARAMETERS p
            WHERE p.SPECIFIC_SCHEMA = r.ROUTINE_SCHEMA
            AND p.SPECIFIC_NAME = r.ROUTINE_NAME
            AND p.PARAMETER_NAME IS NOT NULL
          ) AS parameter_list
        FROM INFORMATION_SCHEMA.ROUTINES r
        ${schemaClause}
        AND r.ROUTINE_NAME = ?
      `,
        queryParams
      );
      if (rows.length === 0) {
        const schemaName = schema || "current schema";
        throw new Error(`Stored procedure '${procedureName}' not found in ${schemaName}`);
      }
      const procedure = rows[0];
      let definition = procedure.ROUTINE_DEFINITION;
      try {
        const schemaValue = schema || await this.getCurrentSchema();
        if (procedure.procedure_type === "procedure") {
          try {
            const [defRows] = await this.pool.query(`
              SHOW CREATE PROCEDURE ${schemaValue}.${procedureName}
            `);
            if (defRows && defRows.length > 0) {
              definition = defRows[0]["Create Procedure"];
            }
          } catch (err) {
            console.error(`Error getting procedure definition with SHOW CREATE: ${err}`);
          }
        } else {
          try {
            const [defRows] = await this.pool.query(`
              SHOW CREATE FUNCTION ${schemaValue}.${procedureName}
            `);
            if (defRows && defRows.length > 0) {
              definition = defRows[0]["Create Function"];
            }
          } catch (innerErr) {
            console.error(`Error getting function definition with SHOW CREATE: ${innerErr}`);
          }
        }
        if (!definition) {
          const [bodyRows] = await this.pool.query(
            `
            SELECT ROUTINE_DEFINITION, ROUTINE_BODY 
            FROM INFORMATION_SCHEMA.ROUTINES
            WHERE ROUTINE_SCHEMA = ? AND ROUTINE_NAME = ?
          `,
            [schemaValue, procedureName]
          );
          if (bodyRows && bodyRows.length > 0) {
            if (bodyRows[0].ROUTINE_DEFINITION) {
              definition = bodyRows[0].ROUTINE_DEFINITION;
            } else if (bodyRows[0].ROUTINE_BODY) {
              definition = bodyRows[0].ROUTINE_BODY;
            }
          }
        }
      } catch (error) {
        console.error(`Error getting procedure/function details: ${error}`);
      }
      return {
        procedure_name: procedure.procedure_name,
        procedure_type: procedure.procedure_type,
        language: "sql",
        // MySQL procedures are generally in SQL
        parameter_list: procedure.parameter_list || "",
        return_type: procedure.routine_type === "function" ? procedure.return_type : void 0,
        definition: definition || void 0
      };
    } catch (error) {
      console.error("Error getting stored procedure detail:", error);
      throw error;
    }
  }
  // Helper method to get current schema (database) name
  async getCurrentSchema() {
    const [rows] = await this.pool.query("SELECT DATABASE() AS DB");
    return rows[0].DB;
  }
  async executeSQL(sql2, options, parameters) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const conn = await this.pool.getConnection();
    try {
      let processedSQL = sql2;
      if (options.maxRows) {
        const statements = sql2.split(";").map((statement) => statement.trim()).filter((statement) => statement.length > 0);
        const processedStatements = statements.map(
          (statement) => SQLRowLimiter.applyMaxRows(statement, options.maxRows)
        );
        processedSQL = processedStatements.join("; ");
        if (sql2.trim().endsWith(";")) {
          processedSQL += ";";
        }
      }
      let results;
      if (parameters && parameters.length > 0) {
        try {
          results = await conn.query({ sql: processedSQL, timeout: this.queryTimeoutMs }, parameters);
        } catch (error) {
          console.error(`[MySQL executeSQL] ERROR: ${error.message}`);
          console.error(`[MySQL executeSQL] SQL: ${processedSQL}`);
          console.error(`[MySQL executeSQL] Parameters: ${JSON.stringify(parameters)}`);
          throw error;
        }
      } else {
        results = await conn.query({ sql: processedSQL, timeout: this.queryTimeoutMs });
      }
      const [firstResult] = results;
      const rows = parseQueryResults(firstResult);
      const rowCount = extractAffectedRows(firstResult);
      return { rows, rowCount };
    } catch (error) {
      console.error("Error executing query:", error);
      throw error;
    } finally {
      conn.release();
    }
  }
};
var mysqlConnector = new MySQLConnector();
ConnectorRegistry.register(mysqlConnector);

// src/connectors/mariadb/index.ts
import * as mariadb from "mariadb";
var MariadbDSNParser = class {
  async parse(dsn, config) {
    const connectionTimeoutSeconds = config?.connectionTimeoutSeconds;
    const queryTimeoutSeconds = config?.queryTimeoutSeconds;
    if (!this.isValidDSN(dsn)) {
      const obfuscatedDSN = obfuscateDSNPassword(dsn);
      const expectedFormat = this.getSampleDSN();
      throw new Error(
        `Invalid MariaDB DSN format.
Provided: ${obfuscatedDSN}
Expected: ${expectedFormat}`
      );
    }
    try {
      const url = new SafeURL(dsn);
      const connectionConfig = {
        host: url.hostname,
        port: url.port ? parseInt(url.port) : 3306,
        database: url.pathname ? url.pathname.substring(1) : "",
        // Remove leading '/' if exists
        user: url.username,
        password: url.password,
        multipleStatements: true,
        // Enable native multi-statement support
        ...connectionTimeoutSeconds !== void 0 && {
          connectTimeout: connectionTimeoutSeconds * 1e3
        },
        ...queryTimeoutSeconds !== void 0 && {
          queryTimeout: queryTimeoutSeconds * 1e3
        }
      };
      url.forEachSearchParam((value, key) => {
        if (key === "sslmode") {
          if (value === "disable") {
            connectionConfig.ssl = void 0;
          } else if (value === "require") {
            connectionConfig.ssl = { rejectUnauthorized: false };
          } else {
            connectionConfig.ssl = {};
          }
        }
      });
      if (url.password && url.password.includes("X-Amz-Credential")) {
        if (connectionConfig.ssl === void 0) {
          connectionConfig.ssl = { rejectUnauthorized: false };
        }
      }
      return connectionConfig;
    } catch (error) {
      throw new Error(
        `Failed to parse MariaDB DSN: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
  getSampleDSN() {
    return "mariadb://root:password@localhost:3306/db?sslmode=require";
  }
  isValidDSN(dsn) {
    try {
      return dsn.startsWith("mariadb://");
    } catch (error) {
      return false;
    }
  }
};
var MariaDBConnector = class _MariaDBConnector {
  constructor() {
    this.id = "mariadb";
    this.name = "MariaDB";
    this.dsnParser = new MariadbDSNParser();
    this.pool = null;
    // Source ID is set by ConnectorManager after cloning
    this.sourceId = "default";
  }
  getId() {
    return this.sourceId;
  }
  clone() {
    return new _MariaDBConnector();
  }
  async connect(dsn, initScript, config) {
    try {
      const connectionConfig = await this.dsnParser.parse(dsn, config);
      this.pool = mariadb.createPool(connectionConfig);
      await this.pool.query("SELECT 1");
    } catch (err) {
      console.error("Failed to connect to MariaDB database:", err);
      throw err;
    }
  }
  async disconnect() {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
    }
  }
  async getSchemas() {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const rows = await this.pool.query(`
        SELECT SCHEMA_NAME 
        FROM INFORMATION_SCHEMA.SCHEMATA
        ORDER BY SCHEMA_NAME
      `);
      return rows.map((row) => row.SCHEMA_NAME);
    } catch (error) {
      console.error("Error getting schemas:", error);
      throw error;
    }
  }
  async getTables(schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE TABLE_SCHEMA = ?" : "WHERE TABLE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema] : [];
      const rows = await this.pool.query(
        `
        SELECT TABLE_NAME 
        FROM INFORMATION_SCHEMA.TABLES 
        ${schemaClause}
        ORDER BY TABLE_NAME
      `,
        queryParams
      );
      return rows.map((row) => row.TABLE_NAME);
    } catch (error) {
      console.error("Error getting tables:", error);
      throw error;
    }
  }
  async tableExists(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE TABLE_SCHEMA = ?" : "WHERE TABLE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema, tableName] : [tableName];
      const rows = await this.pool.query(
        `
        SELECT COUNT(*) AS COUNT
        FROM INFORMATION_SCHEMA.TABLES 
        ${schemaClause} 
        AND TABLE_NAME = ?
      `,
        queryParams
      );
      return rows[0].COUNT > 0;
    } catch (error) {
      console.error("Error checking if table exists:", error);
      throw error;
    }
  }
  async getTableIndexes(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "TABLE_SCHEMA = ?" : "TABLE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema, tableName] : [tableName];
      const indexRows = await this.pool.query(
        `
        SELECT 
          INDEX_NAME,
          COLUMN_NAME,
          NON_UNIQUE,
          SEQ_IN_INDEX
        FROM 
          INFORMATION_SCHEMA.STATISTICS 
        WHERE 
          ${schemaClause}
          AND TABLE_NAME = ? 
        ORDER BY 
          INDEX_NAME, 
          SEQ_IN_INDEX
      `,
        queryParams
      );
      const indexMap = /* @__PURE__ */ new Map();
      for (const row of indexRows) {
        const indexName = row.INDEX_NAME;
        const columnName = row.COLUMN_NAME;
        const isUnique = row.NON_UNIQUE === 0;
        const isPrimary = indexName === "PRIMARY";
        if (!indexMap.has(indexName)) {
          indexMap.set(indexName, {
            columns: [],
            is_unique: isUnique,
            is_primary: isPrimary
          });
        }
        const indexInfo = indexMap.get(indexName);
        indexInfo.columns.push(columnName);
      }
      const results = [];
      indexMap.forEach((indexInfo, indexName) => {
        results.push({
          index_name: indexName,
          column_names: indexInfo.columns,
          is_unique: indexInfo.is_unique,
          is_primary: indexInfo.is_primary
        });
      });
      return results;
    } catch (error) {
      console.error("Error getting table indexes:", error);
      throw error;
    }
  }
  async getTableSchema(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE TABLE_SCHEMA = ?" : "WHERE TABLE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema, tableName] : [tableName];
      const rows = await this.pool.query(
        `
        SELECT
          COLUMN_NAME as column_name,
          DATA_TYPE as data_type,
          IS_NULLABLE as is_nullable,
          COLUMN_DEFAULT as column_default,
          COLUMN_COMMENT as description
        FROM INFORMATION_SCHEMA.COLUMNS
        ${schemaClause}
        AND TABLE_NAME = ?
        ORDER BY ORDINAL_POSITION
      `,
        queryParams
      );
      return rows.map((row) => ({
        ...row,
        description: row.description || null
      }));
    } catch (error) {
      console.error("Error getting table schema:", error);
      throw error;
    }
  }
  async getTableComment(tableName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE TABLE_SCHEMA = ?" : "WHERE TABLE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema, tableName] : [tableName];
      const rows = await this.pool.query(
        `
        SELECT TABLE_COMMENT
        FROM INFORMATION_SCHEMA.TABLES
        ${schemaClause}
        AND TABLE_NAME = ?
      `,
        queryParams
      );
      if (rows.length > 0) {
        return rows[0].TABLE_COMMENT || null;
      }
      return null;
    } catch (error) {
      return null;
    }
  }
  async getStoredProcedures(schema, routineType) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE ROUTINE_SCHEMA = ?" : "WHERE ROUTINE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema] : [];
      let typeFilter = "";
      if (routineType === "function") {
        typeFilter = " AND ROUTINE_TYPE = 'FUNCTION'";
      } else if (routineType === "procedure") {
        typeFilter = " AND ROUTINE_TYPE = 'PROCEDURE'";
      }
      const rows = await this.pool.query(
        `
        SELECT ROUTINE_NAME
        FROM INFORMATION_SCHEMA.ROUTINES
        ${schemaClause}${typeFilter}
        ORDER BY ROUTINE_NAME
      `,
        queryParams
      );
      return rows.map((row) => row.ROUTINE_NAME);
    } catch (error) {
      console.error("Error getting stored procedures:", error);
      throw error;
    }
  }
  async getStoredProcedureDetail(procedureName, schema) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    try {
      const schemaClause = schema ? "WHERE r.ROUTINE_SCHEMA = ?" : "WHERE r.ROUTINE_SCHEMA = DATABASE()";
      const queryParams = schema ? [schema, procedureName] : [procedureName];
      const rows = await this.pool.query(
        `
        SELECT 
          r.ROUTINE_NAME AS procedure_name,
          CASE 
            WHEN r.ROUTINE_TYPE = 'PROCEDURE' THEN 'procedure'
            ELSE 'function'
          END AS procedure_type,
          LOWER(r.ROUTINE_TYPE) AS routine_type,
          r.ROUTINE_DEFINITION,
          r.DTD_IDENTIFIER AS return_type,
          (
            SELECT GROUP_CONCAT(
              CONCAT(p.PARAMETER_NAME, ' ', p.PARAMETER_MODE, ' ', p.DATA_TYPE)
              ORDER BY p.ORDINAL_POSITION
              SEPARATOR ', '
            )
            FROM INFORMATION_SCHEMA.PARAMETERS p
            WHERE p.SPECIFIC_SCHEMA = r.ROUTINE_SCHEMA
            AND p.SPECIFIC_NAME = r.ROUTINE_NAME
            AND p.PARAMETER_NAME IS NOT NULL
          ) AS parameter_list
        FROM INFORMATION_SCHEMA.ROUTINES r
        ${schemaClause}
        AND r.ROUTINE_NAME = ?
      `,
        queryParams
      );
      if (rows.length === 0) {
        const schemaName = schema || "current schema";
        throw new Error(`Stored procedure '${procedureName}' not found in ${schemaName}`);
      }
      const procedure = rows[0];
      let definition = procedure.ROUTINE_DEFINITION;
      try {
        const schemaValue = schema || await this.getCurrentSchema();
        if (procedure.procedure_type === "procedure") {
          try {
            const defRows = await this.pool.query(`
              SHOW CREATE PROCEDURE ${schemaValue}.${procedureName}
            `);
            if (defRows && defRows.length > 0) {
              definition = defRows[0]["Create Procedure"];
            }
          } catch (err) {
            console.error(`Error getting procedure definition with SHOW CREATE: ${err}`);
          }
        } else {
          try {
            const defRows = await this.pool.query(`
              SHOW CREATE FUNCTION ${schemaValue}.${procedureName}
            `);
            if (defRows && defRows.length > 0) {
              definition = defRows[0]["Create Function"];
            }
          } catch (innerErr) {
            console.error(`Error getting function definition with SHOW CREATE: ${innerErr}`);
          }
        }
        if (!definition) {
          const bodyRows = await this.pool.query(
            `
            SELECT ROUTINE_DEFINITION, ROUTINE_BODY 
            FROM INFORMATION_SCHEMA.ROUTINES
            WHERE ROUTINE_SCHEMA = ? AND ROUTINE_NAME = ?
          `,
            [schemaValue, procedureName]
          );
          if (bodyRows && bodyRows.length > 0) {
            if (bodyRows[0].ROUTINE_DEFINITION) {
              definition = bodyRows[0].ROUTINE_DEFINITION;
            } else if (bodyRows[0].ROUTINE_BODY) {
              definition = bodyRows[0].ROUTINE_BODY;
            }
          }
        }
      } catch (error) {
        console.error(`Error getting procedure/function details: ${error}`);
      }
      return {
        procedure_name: procedure.procedure_name,
        procedure_type: procedure.procedure_type,
        language: "sql",
        // MariaDB procedures are generally in SQL
        parameter_list: procedure.parameter_list || "",
        return_type: procedure.routine_type === "function" ? procedure.return_type : void 0,
        definition: definition || void 0
      };
    } catch (error) {
      console.error("Error getting stored procedure detail:", error);
      throw error;
    }
  }
  // Helper method to get current schema (database) name
  async getCurrentSchema() {
    const rows = await this.pool.query("SELECT DATABASE() AS DB");
    return rows[0].DB;
  }
  async executeSQL(sql2, options, parameters) {
    if (!this.pool) {
      throw new Error("Not connected to database");
    }
    const conn = await this.pool.getConnection();
    try {
      let processedSQL = sql2;
      if (options.maxRows) {
        const statements = sql2.split(";").map((statement) => statement.trim()).filter((statement) => statement.length > 0);
        const processedStatements = statements.map(
          (statement) => SQLRowLimiter.applyMaxRows(statement, options.maxRows)
        );
        processedSQL = processedStatements.join("; ");
        if (sql2.trim().endsWith(";")) {
          processedSQL += ";";
        }
      }
      let results;
      if (parameters && parameters.length > 0) {
        try {
          results = await conn.query(processedSQL, parameters);
        } catch (error) {
          console.error(`[MariaDB executeSQL] ERROR: ${error.message}`);
          console.error(`[MariaDB executeSQL] SQL: ${processedSQL}`);
          console.error(`[MariaDB executeSQL] Parameters: ${JSON.stringify(parameters)}`);
          throw error;
        }
      } else {
        results = await conn.query(processedSQL);
      }
      const rows = parseQueryResults(results);
      const rowCount = extractAffectedRows(results);
      return { rows, rowCount };
    } catch (error) {
      console.error("Error executing query:", error);
      throw error;
    } finally {
      conn.release();
    }
  }
};
var mariadbConnector = new MariaDBConnector();
ConnectorRegistry.register(mariadbConnector);

// src/server.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import express from "express";
import path from "path";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";

// src/tools/execute-sql.ts
import { z } from "zod";

// src/utils/response-formatter.ts
function bigIntReplacer(_key, value) {
  if (typeof value === "bigint") {
    return value.toString();
  }
  return value;
}
function formatSuccessResponse(data, meta = {}) {
  return {
    success: true,
    data,
    ...Object.keys(meta).length > 0 ? { meta } : {}
  };
}
function formatErrorResponse(error, code = "ERROR", details) {
  return {
    success: false,
    error,
    code,
    ...details ? { details } : {}
  };
}
function createToolErrorResponse(error, code = "ERROR", details) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(formatErrorResponse(error, code, details), bigIntReplacer, 2),
        mimeType: "application/json"
      }
    ],
    isError: true
  };
}
function createToolSuccessResponse(data, meta = {}) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(formatSuccessResponse(data, meta), bigIntReplacer, 2),
        mimeType: "application/json"
      }
    ]
  };
}

// src/utils/allowed-keywords.ts
var allowedKeywords = {
  postgres: ["select", "with", "explain", "analyze", "show"],
  mysql: ["select", "with", "explain", "analyze", "show", "describe", "desc"],
  mariadb: ["select", "with", "explain", "analyze", "show", "describe", "desc"],
  sqlite: ["select", "with", "explain", "analyze", "pragma"],
  sqlserver: ["select", "with", "explain", "showplan"]
};
function isReadOnlySQL(sql2, connectorType) {
  const cleanedSQL = stripCommentsAndStrings(sql2).trim().toLowerCase();
  if (!cleanedSQL) {
    return true;
  }
  const firstWord = cleanedSQL.split(/\s+/)[0];
  const keywordList = allowedKeywords[connectorType] || [];
  return keywordList.includes(firstWord);
}

// src/requests/store.ts
var RequestStore = class {
  constructor() {
    this.store = /* @__PURE__ */ new Map();
    this.maxPerSource = 100;
  }
  /**
   * Add a request to the store
   * Evicts oldest entry if at capacity
   */
  add(request) {
    const requests = this.store.get(request.sourceId) ?? [];
    requests.push(request);
    if (requests.length > this.maxPerSource) {
      requests.shift();
    }
    this.store.set(request.sourceId, requests);
  }
  /**
   * Get requests, optionally filtered by source
   * Returns newest first
   */
  getAll(sourceId) {
    let requests;
    if (sourceId) {
      requests = [...this.store.get(sourceId) ?? []];
    } else {
      requests = Array.from(this.store.values()).flat();
    }
    return requests.sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }
  /**
   * Get total count of requests across all sources
   */
  getTotal() {
    return Array.from(this.store.values()).reduce((sum, arr) => sum + arr.length, 0);
  }
  /**
   * Clear all requests (useful for testing)
   */
  clear() {
    this.store.clear();
  }
};

// src/requests/index.ts
var requestStore = new RequestStore();

// src/utils/client-identifier.ts
function getClientIdentifier(extra) {
  const userAgent = extra?.requestInfo?.headers?.["user-agent"];
  if (userAgent) {
    return userAgent;
  }
  return "stdio";
}

// src/utils/tool-handler-helpers.ts
function getEffectiveSourceId(sourceId) {
  return sourceId || "default";
}
function createReadonlyViolationMessage(toolName, sourceId, connectorType) {
  return `Tool '${toolName}' cannot execute in readonly mode for source '${sourceId}'. Only read-only SQL operations are allowed: ${allowedKeywords[connectorType]?.join(", ") || "none"}`;
}
function trackToolRequest(metadata, startTime, extra, success, error) {
  requestStore.add({
    id: crypto.randomUUID(),
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    sourceId: metadata.sourceId,
    toolName: metadata.toolName,
    sql: metadata.sql,
    durationMs: Date.now() - startTime,
    client: getClientIdentifier(extra),
    success,
    error
  });
}

// src/tools/execute-sql.ts
var executeSqlSchema = {
  sql: z.string().describe("SQL to execute (multiple statements separated by ;)")
};
function splitSQLStatements(sql2) {
  return sql2.split(";").map((statement) => statement.trim()).filter((statement) => statement.length > 0);
}
function areAllStatementsReadOnly(sql2, connectorType) {
  const statements = splitSQLStatements(sql2);
  return statements.every((statement) => isReadOnlySQL(statement, connectorType));
}
function createExecuteSqlToolHandler(sourceId) {
  return async (args, extra) => {
    const { sql: sql2 } = args;
    const startTime = Date.now();
    const effectiveSourceId = getEffectiveSourceId(sourceId);
    let success = true;
    let errorMessage;
    let result;
    try {
      await ConnectorManager.ensureConnected(sourceId);
      const connector = ConnectorManager.getCurrentConnector(sourceId);
      const actualSourceId = connector.getId();
      const registry = getToolRegistry();
      const toolConfig = registry.getBuiltinToolConfig(BUILTIN_TOOL_EXECUTE_SQL, actualSourceId);
      const isReadonly = toolConfig?.readonly === true;
      if (isReadonly && !areAllStatementsReadOnly(sql2, connector.id)) {
        errorMessage = `Read-only mode is enabled. Only the following SQL operations are allowed: ${allowedKeywords[connector.id]?.join(", ") || "none"}`;
        success = false;
        return createToolErrorResponse(errorMessage, "READONLY_VIOLATION");
      }
      const executeOptions = {
        readonly: toolConfig?.readonly,
        maxRows: toolConfig?.max_rows
      };
      result = await connector.executeSQL(sql2, executeOptions);
      const responseData = {
        rows: result.rows,
        count: result.rowCount,
        source_id: effectiveSourceId
      };
      return createToolSuccessResponse(responseData);
    } catch (error) {
      success = false;
      errorMessage = error.message;
      return createToolErrorResponse(errorMessage, "EXECUTION_ERROR");
    } finally {
      trackToolRequest(
        {
          sourceId: effectiveSourceId,
          toolName: effectiveSourceId === "default" ? "execute_sql" : `execute_sql_${effectiveSourceId}`,
          sql: sql2
        },
        startTime,
        extra,
        success,
        errorMessage
      );
    }
  };
}

// src/tools/search-objects.ts
import { z as z2 } from "zod";
var searchDatabaseObjectsSchema = {
  object_type: z2.enum(["schema", "table", "column", "procedure", "function", "index"]).describe("Object type to search"),
  pattern: z2.string().optional().default("%").describe("LIKE pattern (% = any chars, _ = one char). Default: %"),
  schema: z2.string().optional().describe("Filter to schema"),
  table: z2.string().optional().describe("Filter to table (requires schema; column/index only)"),
  detail_level: z2.enum(["names", "summary", "full"]).default("names").describe("Detail: names (minimal), summary (metadata), full (all)"),
  limit: z2.number().int().positive().max(1e3).default(100).describe("Max results (default: 100, max: 1000)")
};
function likePatternToRegex(pattern) {
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/%/g, ".*").replace(/_/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}
async function getTableRowCount(connector, tableName, schemaName) {
  try {
    if (connector.getTableRowCount) {
      return await connector.getTableRowCount(tableName, schemaName);
    }
    const qualifiedTable = quoteQualifiedIdentifier(tableName, schemaName, connector.id);
    const countQuery = `SELECT COUNT(*) as count FROM ${qualifiedTable}`;
    const result = await connector.executeSQL(countQuery, { maxRows: 1 });
    if (result.rows && result.rows.length > 0) {
      return Number(result.rows[0].count || result.rows[0].COUNT || 0);
    }
  } catch (error) {
    return null;
  }
  return null;
}
async function getTableComment(connector, tableName, schemaName) {
  try {
    if (connector.getTableComment) {
      return await connector.getTableComment(tableName, schemaName);
    }
    return null;
  } catch (error) {
    return null;
  }
}
async function searchSchemas(connector, pattern, detailLevel, limit) {
  const schemas = await connector.getSchemas();
  const regex = likePatternToRegex(pattern);
  const matched = schemas.filter((schema) => regex.test(schema)).slice(0, limit);
  if (detailLevel === "names") {
    return matched.map((name) => ({ name }));
  }
  const results = await Promise.all(
    matched.map(async (schemaName) => {
      try {
        const tables = await connector.getTables(schemaName);
        return {
          name: schemaName,
          table_count: tables.length
        };
      } catch (error) {
        return {
          name: schemaName,
          table_count: 0
        };
      }
    })
  );
  return results;
}
async function searchTables(connector, pattern, schemaFilter, detailLevel, limit) {
  const regex = likePatternToRegex(pattern);
  const results = [];
  let schemasToSearch;
  if (schemaFilter) {
    schemasToSearch = [schemaFilter];
  } else {
    schemasToSearch = await connector.getSchemas();
  }
  for (const schemaName of schemasToSearch) {
    if (results.length >= limit) break;
    try {
      const tables = await connector.getTables(schemaName);
      const matched = tables.filter((table) => regex.test(table));
      for (const tableName of matched) {
        if (results.length >= limit) break;
        if (detailLevel === "names") {
          results.push({
            name: tableName,
            schema: schemaName
          });
        } else if (detailLevel === "summary") {
          try {
            const columns = await connector.getTableSchema(tableName, schemaName);
            const rowCount = await getTableRowCount(connector, tableName, schemaName);
            const comment = await getTableComment(connector, tableName, schemaName);
            results.push({
              name: tableName,
              schema: schemaName,
              column_count: columns.length,
              row_count: rowCount,
              ...comment ? { comment } : {}
            });
          } catch (error) {
            results.push({
              name: tableName,
              schema: schemaName,
              column_count: null,
              row_count: null
            });
          }
        } else {
          try {
            const columns = await connector.getTableSchema(tableName, schemaName);
            const indexes = await connector.getTableIndexes(tableName, schemaName);
            const rowCount = await getTableRowCount(connector, tableName, schemaName);
            const comment = await getTableComment(connector, tableName, schemaName);
            results.push({
              name: tableName,
              schema: schemaName,
              column_count: columns.length,
              row_count: rowCount,
              ...comment ? { comment } : {},
              columns: columns.map((col) => ({
                name: col.column_name,
                type: col.data_type,
                nullable: col.is_nullable === "YES",
                default: col.column_default,
                ...col.description ? { description: col.description } : {}
              })),
              indexes: indexes.map((idx) => ({
                name: idx.index_name,
                columns: idx.column_names,
                unique: idx.is_unique,
                primary: idx.is_primary
              }))
            });
          } catch (error) {
            results.push({
              name: tableName,
              schema: schemaName,
              error: `Unable to fetch full details: ${error.message}`
            });
          }
        }
      }
    } catch (error) {
      continue;
    }
  }
  return results;
}
async function searchColumns(connector, pattern, schemaFilter, tableFilter, detailLevel, limit) {
  const regex = likePatternToRegex(pattern);
  const results = [];
  let schemasToSearch;
  if (schemaFilter) {
    schemasToSearch = [schemaFilter];
  } else {
    schemasToSearch = await connector.getSchemas();
  }
  for (const schemaName of schemasToSearch) {
    if (results.length >= limit) break;
    try {
      let tablesToSearch;
      if (tableFilter) {
        tablesToSearch = [tableFilter];
      } else {
        tablesToSearch = await connector.getTables(schemaName);
      }
      for (const tableName of tablesToSearch) {
        if (results.length >= limit) break;
        try {
          const columns = await connector.getTableSchema(tableName, schemaName);
          const matchedColumns = columns.filter((col) => regex.test(col.column_name));
          for (const column of matchedColumns) {
            if (results.length >= limit) break;
            if (detailLevel === "names") {
              results.push({
                name: column.column_name,
                table: tableName,
                schema: schemaName
              });
            } else {
              results.push({
                name: column.column_name,
                table: tableName,
                schema: schemaName,
                type: column.data_type,
                nullable: column.is_nullable === "YES",
                default: column.column_default,
                ...column.description ? { description: column.description } : {}
              });
            }
          }
        } catch (error) {
          continue;
        }
      }
    } catch (error) {
      continue;
    }
  }
  return results;
}
async function searchProcedures(connector, pattern, schemaFilter, detailLevel, limit, routineType) {
  const regex = likePatternToRegex(pattern);
  const results = [];
  let schemasToSearch;
  if (schemaFilter) {
    schemasToSearch = [schemaFilter];
  } else {
    schemasToSearch = await connector.getSchemas();
  }
  for (const schemaName of schemasToSearch) {
    if (results.length >= limit) break;
    try {
      const procedures = await connector.getStoredProcedures(schemaName, routineType);
      const matched = procedures.filter((proc) => regex.test(proc));
      for (const procName of matched) {
        if (results.length >= limit) break;
        if (detailLevel === "names") {
          results.push({
            name: procName,
            schema: schemaName
          });
        } else {
          try {
            const details = await connector.getStoredProcedureDetail(procName, schemaName);
            results.push({
              name: procName,
              schema: schemaName,
              type: details.procedure_type,
              language: details.language,
              parameters: detailLevel === "full" ? details.parameter_list : void 0,
              return_type: details.return_type,
              definition: detailLevel === "full" ? details.definition : void 0
            });
          } catch (error) {
            results.push({
              name: procName,
              schema: schemaName,
              error: `Unable to fetch details: ${error.message}`
            });
          }
        }
      }
    } catch (error) {
      continue;
    }
  }
  return results;
}
async function searchIndexes(connector, pattern, schemaFilter, tableFilter, detailLevel, limit) {
  const regex = likePatternToRegex(pattern);
  const results = [];
  let schemasToSearch;
  if (schemaFilter) {
    schemasToSearch = [schemaFilter];
  } else {
    schemasToSearch = await connector.getSchemas();
  }
  for (const schemaName of schemasToSearch) {
    if (results.length >= limit) break;
    try {
      let tablesToSearch;
      if (tableFilter) {
        tablesToSearch = [tableFilter];
      } else {
        tablesToSearch = await connector.getTables(schemaName);
      }
      for (const tableName of tablesToSearch) {
        if (results.length >= limit) break;
        try {
          const indexes = await connector.getTableIndexes(tableName, schemaName);
          const matchedIndexes = indexes.filter((idx) => regex.test(idx.index_name));
          for (const index of matchedIndexes) {
            if (results.length >= limit) break;
            if (detailLevel === "names") {
              results.push({
                name: index.index_name,
                table: tableName,
                schema: schemaName
              });
            } else {
              results.push({
                name: index.index_name,
                table: tableName,
                schema: schemaName,
                columns: index.column_names,
                unique: index.is_unique,
                primary: index.is_primary
              });
            }
          }
        } catch (error) {
          continue;
        }
      }
    } catch (error) {
      continue;
    }
  }
  return results;
}
function createSearchDatabaseObjectsToolHandler(sourceId) {
  return async (args, extra) => {
    const {
      object_type,
      pattern = "%",
      schema,
      table,
      detail_level = "names",
      limit = 100
    } = args;
    const startTime = Date.now();
    const effectiveSourceId = getEffectiveSourceId(sourceId);
    let success = true;
    let errorMessage;
    try {
      await ConnectorManager.ensureConnected(sourceId);
      const connector = ConnectorManager.getCurrentConnector(sourceId);
      if (table) {
        if (!schema) {
          success = false;
          errorMessage = "The 'table' parameter requires 'schema' to be specified";
          return createToolErrorResponse(errorMessage, "SCHEMA_REQUIRED");
        }
        if (!["column", "index"].includes(object_type)) {
          success = false;
          errorMessage = `The 'table' parameter only applies to object_type 'column' or 'index', not '${object_type}'`;
          return createToolErrorResponse(errorMessage, "INVALID_TABLE_FILTER");
        }
      }
      if (schema) {
        const schemas = await connector.getSchemas();
        if (!schemas.includes(schema)) {
          success = false;
          errorMessage = `Schema '${schema}' does not exist. Available schemas: ${schemas.join(", ")}`;
          return createToolErrorResponse(errorMessage, "SCHEMA_NOT_FOUND");
        }
      }
      let results = [];
      switch (object_type) {
        case "schema":
          results = await searchSchemas(connector, pattern, detail_level, limit);
          break;
        case "table":
          results = await searchTables(connector, pattern, schema, detail_level, limit);
          break;
        case "column":
          results = await searchColumns(connector, pattern, schema, table, detail_level, limit);
          break;
        case "procedure":
          results = await searchProcedures(connector, pattern, schema, detail_level, limit, "procedure");
          break;
        case "function":
          results = await searchProcedures(connector, pattern, schema, detail_level, limit, "function");
          break;
        case "index":
          results = await searchIndexes(connector, pattern, schema, table, detail_level, limit);
          break;
        default:
          success = false;
          errorMessage = `Unsupported object_type: ${object_type}`;
          return createToolErrorResponse(errorMessage, "INVALID_OBJECT_TYPE");
      }
      return createToolSuccessResponse({
        object_type,
        pattern,
        schema,
        table,
        detail_level,
        count: results.length,
        results,
        truncated: results.length === limit
      });
    } catch (error) {
      success = false;
      errorMessage = error.message;
      return createToolErrorResponse(
        `Error searching database objects: ${errorMessage}`,
        "SEARCH_ERROR"
      );
    } finally {
      trackToolRequest(
        {
          sourceId: effectiveSourceId,
          toolName: effectiveSourceId === "default" ? "search_objects" : `search_objects_${effectiveSourceId}`,
          sql: `search_objects(object_type=${object_type}, pattern=${pattern}, schema=${schema || "all"}, table=${table || "all"}, detail_level=${detail_level})`
        },
        startTime,
        extra,
        success,
        errorMessage
      );
    }
  };
}

// src/utils/tool-metadata.ts
import { z as z3 } from "zod";

// src/utils/normalize-id.ts
function normalizeSourceId(id) {
  return id.replace(/[^a-zA-Z0-9]/g, "_");
}

// src/utils/tool-metadata.ts
function zodToParameters(schema) {
  const parameters = [];
  for (const [key, zodType] of Object.entries(schema)) {
    const description = zodType.description || "";
    const required = !(zodType instanceof z3.ZodOptional);
    let type = "string";
    if (zodType instanceof z3.ZodString) {
      type = "string";
    } else if (zodType instanceof z3.ZodNumber) {
      type = "number";
    } else if (zodType instanceof z3.ZodBoolean) {
      type = "boolean";
    } else if (zodType instanceof z3.ZodArray) {
      type = "array";
    } else if (zodType instanceof z3.ZodObject) {
      type = "object";
    }
    parameters.push({
      name: key,
      type,
      required,
      description
    });
  }
  return parameters;
}
function getExecuteSqlMetadata(sourceId) {
  const sourceIds = ConnectorManager.getAvailableSourceIds();
  const sourceConfig = ConnectorManager.getSourceConfig(sourceId);
  const dbType = sourceConfig.type;
  const isSingleSource = sourceIds.length === 1;
  const registry = getToolRegistry();
  const toolConfig = registry.getBuiltinToolConfig(BUILTIN_TOOL_EXECUTE_SQL, sourceId);
  const executeOptions = {
    readonly: toolConfig?.readonly,
    maxRows: toolConfig?.max_rows
  };
  const toolName = isSingleSource ? "execute_sql" : `execute_sql_${normalizeSourceId(sourceId)}`;
  const title = isSingleSource ? `Execute SQL (${dbType})` : `Execute SQL on ${sourceId} (${dbType})`;
  const readonlyNote = executeOptions.readonly ? " [READ-ONLY MODE]" : "";
  const maxRowsNote = executeOptions.maxRows ? ` (limited to ${executeOptions.maxRows} rows)` : "";
  const description = isSingleSource ? `Execute SQL queries on the ${dbType} database${readonlyNote}${maxRowsNote}` : `Execute SQL queries on the '${sourceId}' ${dbType} database${readonlyNote}${maxRowsNote}`;
  const isReadonly = executeOptions.readonly === true;
  const annotations = {
    title,
    readOnlyHint: isReadonly,
    destructiveHint: !isReadonly,
    // Can be destructive if not readonly
    // In readonly mode, queries are more predictable (though still not strictly idempotent due to data changes)
    // In write mode, queries are definitely not idempotent
    idempotentHint: false,
    // Database operations are always against internal/closed systems, not open-world
    openWorldHint: false
  };
  return {
    name: toolName,
    description,
    schema: executeSqlSchema,
    annotations
  };
}
function getSearchObjectsMetadata(sourceId) {
  const sourceIds = ConnectorManager.getAvailableSourceIds();
  const sourceConfig = ConnectorManager.getSourceConfig(sourceId);
  const dbType = sourceConfig.type;
  const isSingleSource = sourceIds.length === 1;
  const toolName = isSingleSource ? "search_objects" : `search_objects_${normalizeSourceId(sourceId)}`;
  const title = isSingleSource ? `Search Database Objects (${dbType})` : `Search Database Objects on ${sourceId} (${dbType})`;
  const description = isSingleSource ? `Search and list database objects (schemas, tables, columns, procedures, functions, indexes) on the ${dbType} database` : `Search and list database objects (schemas, tables, columns, procedures, functions, indexes) on the '${sourceId}' ${dbType} database`;
  return {
    name: toolName,
    description,
    title
  };
}
function customParamsToToolParams(params) {
  if (!params || params.length === 0) {
    return [];
  }
  return params.map((param) => ({
    name: param.name,
    type: param.type,
    required: param.required !== false && param.default === void 0,
    description: param.description
  }));
}
function buildExecuteSqlTool(sourceId, toolConfig) {
  const executeSqlMetadata = getExecuteSqlMetadata(sourceId);
  const executeSqlParameters = zodToParameters(executeSqlMetadata.schema);
  const readonly = toolConfig && "readonly" in toolConfig ? toolConfig.readonly : void 0;
  const max_rows = toolConfig && "max_rows" in toolConfig ? toolConfig.max_rows : void 0;
  return {
    name: executeSqlMetadata.name,
    description: executeSqlMetadata.description,
    parameters: executeSqlParameters,
    readonly,
    max_rows
  };
}
function buildSearchObjectsTool(sourceId) {
  const searchMetadata = getSearchObjectsMetadata(sourceId);
  return {
    name: searchMetadata.name,
    description: searchMetadata.description,
    parameters: [
      {
        name: "object_type",
        type: "string",
        required: true,
        description: "Object type to search"
      },
      {
        name: "pattern",
        type: "string",
        required: false,
        description: "LIKE pattern (% = any chars, _ = one char). Default: %"
      },
      {
        name: "schema",
        type: "string",
        required: false,
        description: "Filter to schema"
      },
      {
        name: "table",
        type: "string",
        required: false,
        description: "Filter to table (requires schema; column/index only)"
      },
      {
        name: "detail_level",
        type: "string",
        required: false,
        description: "Detail: names (minimal), summary (metadata), full (all)"
      },
      {
        name: "limit",
        type: "integer",
        required: false,
        description: "Max results (default: 100, max: 1000)"
      }
    ],
    readonly: true
    // search_objects is always readonly
  };
}
function buildCustomTool(toolConfig) {
  return {
    name: toolConfig.name,
    description: toolConfig.description,
    parameters: customParamsToToolParams(toolConfig.parameters),
    statement: toolConfig.statement,
    readonly: toolConfig.readonly,
    max_rows: toolConfig.max_rows
  };
}
function getToolsForSource(sourceId) {
  const registry = getToolRegistry();
  const enabledToolConfigs = registry.getEnabledToolConfigs(sourceId);
  return enabledToolConfigs.map((toolConfig) => {
    if (toolConfig.name === "execute_sql") {
      return buildExecuteSqlTool(sourceId, toolConfig);
    } else if (toolConfig.name === "search_objects") {
      return buildSearchObjectsTool(sourceId);
    } else {
      return buildCustomTool(toolConfig);
    }
  });
}

// src/tools/custom-tool-handler.ts
import { z as z4 } from "zod";
function buildZodSchemaFromParameters(parameters) {
  if (!parameters || parameters.length === 0) {
    return {};
  }
  const schemaShape = {};
  for (const param of parameters) {
    let fieldSchema;
    switch (param.type) {
      case "string":
        fieldSchema = z4.string().describe(param.description);
        break;
      case "integer":
        fieldSchema = z4.number().int().describe(param.description);
        break;
      case "float":
        fieldSchema = z4.number().describe(param.description);
        break;
      case "boolean":
        fieldSchema = z4.boolean().describe(param.description);
        break;
      case "array":
        fieldSchema = z4.array(z4.unknown()).describe(param.description);
        break;
      default:
        throw new Error(`Unsupported parameter type: ${param.type}`);
    }
    if (param.allowed_values && param.allowed_values.length > 0) {
      if (param.type === "string") {
        fieldSchema = z4.enum(param.allowed_values).describe(param.description);
      } else {
        fieldSchema = fieldSchema.refine(
          (val) => param.allowed_values.includes(val),
          {
            message: `Value must be one of: ${param.allowed_values.join(", ")}`
          }
        );
      }
    }
    if (param.default !== void 0 || param.required === false) {
      fieldSchema = fieldSchema.optional();
    }
    schemaShape[param.name] = fieldSchema;
  }
  return schemaShape;
}
function createCustomToolHandler(toolConfig) {
  const zodSchemaShape = buildZodSchemaFromParameters(toolConfig.parameters);
  const zodSchema = z4.object(zodSchemaShape);
  return async (args, extra) => {
    const startTime = Date.now();
    let success = true;
    let errorMessage;
    let paramValues = [];
    try {
      const validatedArgs = zodSchema.parse(args);
      await ConnectorManager.ensureConnected(toolConfig.source);
      const connector = ConnectorManager.getCurrentConnector(toolConfig.source);
      const executeOptions = {
        readonly: toolConfig.readonly,
        maxRows: toolConfig.max_rows
      };
      const isReadonly = executeOptions.readonly === true;
      if (isReadonly && !isReadOnlySQL(toolConfig.statement, connector.id)) {
        errorMessage = createReadonlyViolationMessage(toolConfig.name, toolConfig.source, connector.id);
        success = false;
        return createToolErrorResponse(errorMessage, "READONLY_VIOLATION");
      }
      paramValues = mapArgumentsToArray(
        toolConfig.parameters,
        validatedArgs
      );
      const result = await connector.executeSQL(
        toolConfig.statement,
        executeOptions,
        paramValues
      );
      const responseData = {
        rows: result.rows,
        count: result.rowCount,
        source_id: toolConfig.source
      };
      return createToolSuccessResponse(responseData);
    } catch (error) {
      success = false;
      errorMessage = error.message;
      if (error instanceof z4.ZodError) {
        const issues = error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        errorMessage = `Parameter validation failed: ${issues}`;
      } else {
        errorMessage = `${errorMessage}

SQL: ${toolConfig.statement}
Parameters: ${JSON.stringify(paramValues)}`;
      }
      return createToolErrorResponse(errorMessage, "EXECUTION_ERROR");
    } finally {
      trackToolRequest(
        {
          sourceId: toolConfig.source,
          toolName: toolConfig.name,
          sql: toolConfig.statement
        },
        startTime,
        extra,
        success,
        errorMessage
      );
    }
  };
}

// src/tools/index.ts
function registerTools(server) {
  const sourceIds = ConnectorManager.getAvailableSourceIds();
  if (sourceIds.length === 0) {
    throw new Error("No database sources configured");
  }
  const registry = getToolRegistry();
  for (const sourceId of sourceIds) {
    const enabledTools = registry.getEnabledToolConfigs(sourceId);
    for (const toolConfig of enabledTools) {
      if (toolConfig.name === BUILTIN_TOOL_EXECUTE_SQL) {
        registerExecuteSqlTool(server, sourceId);
      } else if (toolConfig.name === BUILTIN_TOOL_SEARCH_OBJECTS) {
        registerSearchObjectsTool(server, sourceId);
      } else {
        registerCustomTool(server, sourceId, toolConfig);
      }
    }
  }
}
function registerExecuteSqlTool(server, sourceId) {
  const metadata = getExecuteSqlMetadata(sourceId);
  server.registerTool(
    metadata.name,
    {
      description: metadata.description,
      inputSchema: metadata.schema,
      annotations: metadata.annotations
    },
    createExecuteSqlToolHandler(sourceId)
  );
}
function registerSearchObjectsTool(server, sourceId) {
  const metadata = getSearchObjectsMetadata(sourceId);
  server.registerTool(
    metadata.name,
    {
      description: metadata.description,
      inputSchema: searchDatabaseObjectsSchema,
      annotations: {
        title: metadata.title,
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    createSearchDatabaseObjectsToolHandler(sourceId)
  );
}
function registerCustomTool(server, sourceId, toolConfig) {
  const sourceConfig = ConnectorManager.getSourceConfig(sourceId);
  const dbType = sourceConfig.type;
  const isReadOnly = isReadOnlySQL(toolConfig.statement, dbType);
  const zodSchema = buildZodSchemaFromParameters(toolConfig.parameters);
  server.registerTool(
    toolConfig.name,
    {
      description: toolConfig.description,
      inputSchema: zodSchema,
      annotations: {
        title: `${toolConfig.name} (${dbType})`,
        readOnlyHint: isReadOnly,
        destructiveHint: !isReadOnly,
        idempotentHint: isReadOnly,
        openWorldHint: false
      }
    },
    createCustomToolHandler(toolConfig)
  );
}

// src/api/sources.ts
function transformSourceConfig(source) {
  if (!source.type && source.dsn) {
    const inferredType = getDatabaseTypeFromDSN(source.dsn);
    if (inferredType) {
      source.type = inferredType;
    }
  }
  if (!source.type) {
    throw new Error(`Source ${source.id} is missing required type field`);
  }
  const dataSource = {
    id: source.id,
    type: source.type
  };
  if (source.description) {
    dataSource.description = source.description;
  }
  if (source.host) {
    dataSource.host = source.host;
  }
  if (source.port !== void 0) {
    dataSource.port = source.port;
  }
  if (source.database) {
    dataSource.database = source.database;
  }
  if (source.user) {
    dataSource.user = source.user;
  }
  if (source.ssh_host) {
    const sshTunnel = {
      enabled: true,
      ssh_host: source.ssh_host
    };
    if (source.ssh_port !== void 0) {
      sshTunnel.ssh_port = source.ssh_port;
    }
    if (source.ssh_user) {
      sshTunnel.ssh_user = source.ssh_user;
    }
    dataSource.ssh_tunnel = sshTunnel;
  }
  dataSource.tools = getToolsForSource(source.id);
  return dataSource;
}
function listSources(req, res) {
  try {
    const sourceConfigs = ConnectorManager.getAllSourceConfigs();
    const sources = sourceConfigs.map((config) => {
      return transformSourceConfig(config);
    });
    res.json(sources);
  } catch (error) {
    console.error("Error listing sources:", error);
    const errorResponse = {
      error: error instanceof Error ? error.message : "Internal server error"
    };
    res.status(500).json(errorResponse);
  }
}
function getSource(req, res) {
  try {
    const sourceId = req.params.sourceId;
    const sourceConfig = ConnectorManager.getSourceConfig(sourceId);
    if (!sourceConfig) {
      const errorResponse = {
        error: "Source not found",
        source_id: sourceId
      };
      res.status(404).json(errorResponse);
      return;
    }
    const dataSource = transformSourceConfig(sourceConfig);
    res.json(dataSource);
  } catch (error) {
    console.error(`Error getting source ${req.params.sourceId}:`, error);
    const errorResponse = {
      error: error instanceof Error ? error.message : "Internal server error"
    };
    res.status(500).json(errorResponse);
  }
}

// src/api/requests.ts
function listRequests(req, res) {
  try {
    const sourceId = req.query.source_id;
    const requests = requestStore.getAll(sourceId);
    res.json({
      requests,
      total: requests.length
    });
  } catch (error) {
    console.error("Error listing requests:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Internal server error"
    });
  }
}

// src/utils/startup-table.ts
var BOX = {
  topLeft: "\u250C",
  topRight: "\u2510",
  bottomLeft: "\u2514",
  bottomRight: "\u2518",
  horizontal: "\u2500",
  vertical: "\u2502",
  leftT: "\u251C",
  rightT: "\u2524",
  bullet: "\u2022"
};
function parseHostAndDatabase(source) {
  if (source.dsn) {
    const parsed = parseConnectionInfoFromDSN(source.dsn);
    if (parsed) {
      if (parsed.type === "sqlite") {
        return { host: "", database: parsed.database || ":memory:" };
      }
      if (!parsed.host) {
        return { host: "", database: parsed.database || "" };
      }
      const port = parsed.port ?? getDefaultPortForType(parsed.type);
      const host2 = port ? `${parsed.host}:${port}` : parsed.host;
      return { host: host2, database: parsed.database || "" };
    }
    return { host: "unknown", database: "" };
  }
  const host = source.host ? source.port ? `${source.host}:${source.port}` : source.host : "";
  const database = source.database || "";
  return { host, database };
}
function horizontalLine(width, left, right) {
  return left + BOX.horizontal.repeat(width - 2) + right;
}
function fitString(str, width) {
  if (str.length > width) {
    return str.slice(0, width - 1) + "\u2026";
  }
  return str.padEnd(width);
}
function formatHostDatabase(host, database) {
  return host ? database ? `${host}/${database}` : host : database || "";
}
function generateStartupTable(sources) {
  if (sources.length === 0) {
    return "";
  }
  const idTypeWidth = Math.max(
    20,
    ...sources.map((s) => `${s.id} (${s.type})`.length)
  );
  const hostDbWidth = Math.max(
    24,
    ...sources.map((s) => formatHostDatabase(s.host, s.database).length)
  );
  const modeWidth = Math.max(
    10,
    ...sources.map((s) => {
      const modes = [];
      if (s.isDemo) modes.push("DEMO");
      if (s.readonly) modes.push("READ-ONLY");
      return modes.join(" ").length;
    })
  );
  const totalWidth = 2 + idTypeWidth + 3 + hostDbWidth + 3 + modeWidth + 2;
  const lines = [];
  for (let i = 0; i < sources.length; i++) {
    const source = sources[i];
    const isFirst = i === 0;
    const isLast = i === sources.length - 1;
    if (isFirst) {
      lines.push(horizontalLine(totalWidth, BOX.topLeft, BOX.topRight));
    }
    const idType = fitString(`${source.id} (${source.type})`, idTypeWidth);
    const hostDb = fitString(
      formatHostDatabase(source.host, source.database),
      hostDbWidth
    );
    const modes = [];
    if (source.isDemo) modes.push("DEMO");
    if (source.readonly) modes.push("READ-ONLY");
    const modeStr = fitString(modes.join(" "), modeWidth);
    lines.push(
      `${BOX.vertical} ${idType} ${BOX.vertical} ${hostDb} ${BOX.vertical} ${modeStr} ${BOX.vertical}`
    );
    lines.push(horizontalLine(totalWidth, BOX.leftT, BOX.rightT));
    for (const tool of source.tools) {
      const toolLine = `  ${BOX.bullet} ${tool}`;
      lines.push(
        `${BOX.vertical} ${fitString(toolLine, totalWidth - 4)} ${BOX.vertical}`
      );
    }
    if (isLast) {
      lines.push(horizontalLine(totalWidth, BOX.bottomLeft, BOX.bottomRight));
    } else {
      lines.push(horizontalLine(totalWidth, BOX.leftT, BOX.rightT));
    }
  }
  return lines.join("\n");
}
function buildSourceDisplayInfo(sourceConfigs, getToolsForSource2, isDemo) {
  return sourceConfigs.map((source) => {
    const { host, database } = parseHostAndDatabase(source);
    return {
      id: source.id,
      type: source.type || "sqlite",
      host,
      database,
      readonly: source.readonly || false,
      isDemo,
      tools: getToolsForSource2(source.id)
    };
  });
}

// src/server.ts
var __filename = fileURLToPath(import.meta.url);
var __dirname = path.dirname(__filename);
var packageJsonPath = path.join(__dirname, "..", "package.json");
var packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
var SERVER_NAME = "DBHub MCP Server";
var SERVER_VERSION = packageJson.version;
function generateBanner(version, modes = []) {
  const modeText = modes.length > 0 ? ` [${modes.join(" | ")}]` : "";
  return `
 _____  ____  _   _       _     
|  __ \\|  _ \\| | | |     | |    
| |  | | |_) | |_| |_   _| |__  
| |  | |  _ <|  _  | | | | '_ \\ 
| |__| | |_) | | | | |_| | |_) |
|_____/|____/|_| |_|\\__,_|_.__/ 
                                
v${version}${modeText} - Minimal Database MCP Server
`;
}
async function main() {
  try {
    const sourceConfigsData = await resolveSourceConfigs();
    if (!sourceConfigsData) {
      const samples = ConnectorRegistry.getAllSampleDSNs();
      const sampleFormats = Object.entries(samples).map(([id, dsn]) => `  - ${id}: ${dsn}`).join("\n");
      console.error(`
ERROR: Database connection configuration is required.
Please provide configuration in one of these ways (in order of priority):

1. Use demo mode: --demo (uses in-memory SQLite with sample employee database)
2. TOML config file: --config=path/to/dbhub.toml or ./dbhub.toml
3. Command line argument: --dsn="your-connection-string"
4. Environment variable: export DSN="your-connection-string"
5. .env file: DSN=your-connection-string

Example DSN formats:
${sampleFormats}

Example TOML config (dbhub.toml):
  [[sources]]
  id = "my_db"
  dsn = "postgres://user:pass@localhost:5432/dbname"

See documentation for more details on configuring database connections.
`);
      process.exit(1);
    }
    const connectorManager = new ConnectorManager();
    const sources = sourceConfigsData.sources;
    console.error(`Configuration source: ${sourceConfigsData.source}`);
    await connectorManager.connectWithSources(sources);
    const { initializeToolRegistry } = await import("./registry-BEWDMPAS.js");
    initializeToolRegistry({
      sources: sourceConfigsData.sources,
      tools: sourceConfigsData.tools
    });
    console.error("Tool registry initialized");
    const createServer = () => {
      const server = new McpServer({
        name: SERVER_NAME,
        version: SERVER_VERSION
      });
      registerTools(server);
      return server;
    };
    const transportData = resolveTransport();
    const port = transportData.type === "http" ? resolvePort().port : null;
    const activeModes = [];
    const modeDescriptions = [];
    const isDemo = isDemoMode();
    if (isDemo) {
      activeModes.push("DEMO");
      modeDescriptions.push("using sample employee database");
    }
    if (activeModes.length > 0) {
      console.error(`Running in ${activeModes.join(" and ")} mode - ${modeDescriptions.join(", ")}`);
    }
    console.error(generateBanner(SERVER_VERSION, activeModes));
    const sourceDisplayInfos = buildSourceDisplayInfo(
      sources,
      (sourceId) => getToolsForSource(sourceId).map((t) => t.readonly ? `\u{1F512} ${t.name}` : t.name),
      isDemo
    );
    console.error(generateStartupTable(sourceDisplayInfos));
    if (transportData.type === "http") {
      const app = express();
      app.use(express.json());
      app.use((req, res, next) => {
        const origin = req.headers.origin;
        res.header("Access-Control-Allow-Origin", origin || "http://localhost");
        res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.header("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id");
        res.header("Access-Control-Allow-Credentials", "true");
        if (req.method === "OPTIONS") {
          return res.sendStatus(200);
        }
        next();
      });
      const frontendPath = path.join(__dirname, "public");
      app.use(express.static(frontendPath));
      app.get("/healthz", (req, res) => {
        res.status(200).send("OK");
      });
      app.get("/api/sources", listSources);
      app.get("/api/sources/:sourceId", getSource);
      app.get("/api/requests", listRequests);
      app.get("/mcp", (req, res) => {
        res.status(405).json({
          error: "Method Not Allowed",
          message: "SSE streaming is not supported in stateless mode. Use POST requests with JSON responses."
        });
      });
      app.post("/mcp", async (req, res) => {
        try {
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: void 0,
            // Disable session management for stateless mode
            enableJsonResponse: true
            // Use JSON responses (SSE not supported in stateless mode)
          });
          const server = createServer();
          await server.connect(transport);
          await transport.handleRequest(req, res, req.body);
        } catch (error) {
          console.error("Error handling request:", error);
          if (!res.headersSent) {
            res.status(500).json({ error: "Internal server error" });
          }
        }
      });
      if (process.env.NODE_ENV !== "development") {
        app.get("*", (req, res) => {
          res.sendFile(path.join(frontendPath, "index.html"));
        });
      }
      app.listen(port, "0.0.0.0", () => {
        if (process.env.NODE_ENV === "development") {
          console.error("Development mode detected!");
          console.error("   Workbench dev server (with HMR): http://localhost:5173");
          console.error("   Backend API: http://localhost:8080");
          console.error("");
        } else {
          console.error(`Workbench at http://localhost:${port}/`);
        }
        console.error(`MCP server endpoint at http://localhost:${port}/mcp`);
      });
    } else {
      const server = createServer();
      const transport = new StdioServerTransport();
      await server.connect(transport);
      console.error("MCP server running on stdio");
      process.on("SIGINT", async () => {
        console.error("Shutting down...");
        await transport.close();
        process.exit(0);
      });
    }
  } catch (err) {
    console.error("Fatal error:", err);
    process.exit(1);
  }
}

// src/index.ts
main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
