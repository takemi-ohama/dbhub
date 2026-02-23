// src/config/demo-loader.ts
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
var __filename = fileURLToPath(import.meta.url);
var __dirname = path.dirname(__filename);
var DEMO_DATA_DIR;
var projectRootPath = path.join(__dirname, "..", "..", "..");
var projectResourcesPath = path.join(projectRootPath, "demo", "employee-sqlite");
var distPath = path.join(__dirname, "demo", "employee-sqlite");
if (fs.existsSync(projectResourcesPath)) {
  DEMO_DATA_DIR = projectResourcesPath;
} else if (fs.existsSync(distPath)) {
  DEMO_DATA_DIR = distPath;
} else {
  DEMO_DATA_DIR = path.join(process.cwd(), "demo", "employee-sqlite");
  if (!fs.existsSync(DEMO_DATA_DIR)) {
    throw new Error(`Could not find employee-sqlite resources in any of the expected locations: 
      - ${projectResourcesPath}
      - ${distPath}
      - ${DEMO_DATA_DIR}`);
  }
}
function loadSqlFile(fileName) {
  const filePath = path.join(DEMO_DATA_DIR, fileName);
  return fs.readFileSync(filePath, "utf8");
}
function getInMemorySqliteDSN() {
  return "sqlite:///:memory:";
}
function getSqliteInMemorySetupSql() {
  let sql = loadSqlFile("employee.sql");
  const readRegex = /\.read\s+([a-zA-Z0-9_]+\.sql)/g;
  let match;
  while ((match = readRegex.exec(sql)) !== null) {
    const includePath = match[1];
    const includeContent = loadSqlFile(includePath);
    sql = sql.replace(match[0], includeContent);
  }
  return sql;
}
export {
  getInMemorySqliteDSN,
  getSqliteInMemorySetupSql,
  loadSqlFile
};
