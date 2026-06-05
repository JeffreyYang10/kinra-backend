import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";

const envPath = path.resolve(".env");
const token = await promptHidden("Paste fresh PSA access token: ");

if (!token.trim()) {
  console.error("No token entered.");
  process.exit(1);
}

const existing = fs.existsSync(envPath)
  ? fs.readFileSync(envPath, "utf8")
  : fs.readFileSync(path.resolve(".env.example"), "utf8");

const next = upsertEnv(existing, "PSA_ACCESS_TOKEN", token.trim());
fs.writeFileSync(envPath, next.endsWith("\n") ? next : `${next}\n`, { mode: 0o600 });
console.log("PSA access token saved to backend/psa-proxy/.env");

function upsertEnv(contents, key, value) {
  const escaped = value.replaceAll("\\", "\\\\").replaceAll("\n", "");
  const line = `${key}=${escaped}`;
  const pattern = new RegExp(`^${key}=.*$`, "m");
  if (pattern.test(contents)) {
    return contents.replace(pattern, line);
  }
  return `${contents.trimEnd()}\n${line}\n`;
}

function promptHidden(question) {
  return new Promise((resolve) => {
    const input = process.stdin;
    const output = process.stdout;
    const rl = readline.createInterface({ input, output, terminal: true });

    const originalWrite = output.write.bind(output);
    output.write = (chunk, encoding, callback) => {
      const text = String(chunk);
      if (text.includes(question) || text.includes("\n")) {
        return originalWrite(chunk, encoding, callback);
      }
      return true;
    };

    rl.question(question, (answer) => {
      output.write = originalWrite;
      rl.close();
      output.write("\n");
      resolve(answer);
    });
  });
}
