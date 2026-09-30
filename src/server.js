// Entry point: load config, open the database, start listening, shut down cleanly.
// Run: npm start   (needs JWT_SECRET; see .env.example)
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { openDatabase } from "./db.js";

const config = loadConfig();
const db = openDatabase(config.DATABASE_PATH);
const server = createApp({ db, config }).listen(config.PORT, () => {
  console.log(`auth API listening on http://localhost:${config.PORT}`);
});

// Finish in-flight requests and close the database on Ctrl+C or a container stop.
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}
