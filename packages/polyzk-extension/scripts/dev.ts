import { watch } from "chokidar";
import { spawn } from "child_process";
import { join } from "path";

const rootDir = join(import.meta.dir, "..");
const srcDir = join(rootDir, "src");

let buildProcess: ReturnType<typeof spawn> | null = null;
let debounceTimer: ReturnType<typeof setTimeout> | null = null;

async function build() {
  if (buildProcess) {
    buildProcess.kill();
  }

  console.log("\n🔨 Building...");

  buildProcess = spawn("bun", ["run", "build"], {
    cwd: rootDir,
    stdio: "inherit",
  });

  buildProcess.on("close", (code) => {
    if (code === 0) {
      console.log("✅ Build complete! Reload extension in Chrome (Ctrl+R on extensions page)");
      // Trigger reload via WebSocket if connected
      notifyReload();
    } else {
      console.log("❌ Build failed");
    }
    buildProcess = null;
  });
}

// WebSocket server for live reload
const reloadClients: Set<any> = new Set();

const reloadServer = Bun.serve({
  port: 35729,
  fetch(req, server) {
    if (server.upgrade(req)) {
      return;
    }
    return new Response("Polynight Dev Server", { status: 200 });
  },
  websocket: {
    open(ws) {
      reloadClients.add(ws);
      console.log("🔌 Extension connected for live reload");
    },
    close(ws) {
      reloadClients.delete(ws);
    },
    message() {},
  },
});

function notifyReload() {
  for (const client of reloadClients) {
    try {
      client.send(JSON.stringify({ type: "reload" }));
    } catch (e) {
      reloadClients.delete(client);
    }
  }
}

// Watch for changes
const watcher = watch([srcDir, join(rootDir, "manifest.json")], {
  ignoreInitial: true,
  ignored: /node_modules/,
});

watcher.on("all", (event, path) => {
  console.log(`\n📁 ${event}: ${path.replace(rootDir, "")}`);

  // Debounce builds
  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }

  debounceTimer = setTimeout(() => {
    build();
  }, 100);
});

// Initial build
console.log("🚀 Polynight Dev Server");
console.log(`📡 Live reload server running on ws://localhost:${reloadServer.port}`);
console.log("👀 Watching for changes in src/...\n");

await build();

// Keep the process running
process.on("SIGINT", () => {
  console.log("\n👋 Shutting down...");
  watcher.close();
  reloadServer.stop();
  process.exit(0);
});
