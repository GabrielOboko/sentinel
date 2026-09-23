import pg from "pg";
import "dotenv/config";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/sentinel",
  max: 10,
});

pool.on("error", (err) => {
  console.error("[db] unexpected error on idle client", err);
});
