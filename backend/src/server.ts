import Fastify from "fastify";
import cors from "@fastify/cors";
import "dotenv/config";
import { targetsRoutes } from "./api/targets.js";
import { scansRoutes } from "./api/scans.js";

const app = Fastify({ logger: true });

await app.register(cors, { origin: process.env.CORS_ORIGIN ?? "http://localhost:5173" });

app.get("/health", async () => ({ status: "ok" }));

await app.register(targetsRoutes);
await app.register(scansRoutes);

const port = Number(process.env.PORT ?? 4000);
app.listen({ port, host: "0.0.0.0" }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
