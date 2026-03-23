import { readFile, writeFile, readdir, stat } from "fs/promises";
import { resolve, join, dirname } from "path";
import { existsSync } from "fs";

const root = resolve("node_modules/@tideorg/js/dist");

async function patchDir(dir) {
  const entries = await readdir(dir);
  for (const entry of entries) {
    const full = join(dir, entry);
    const s = await stat(full);
    if (s.isDirectory()) {
      await patchDir(full);
    } else if (entry.endsWith(".js")) {
      let content = await readFile(full, "utf-8");
      const patched = content.replace(
        /from (['"])(\.\.?\/[^'"]+)\1/g,
        (match, quote, importPath) => {
          if (importPath.endsWith(".js")) return match;
          const base = dirname(full);
          const resolved = resolve(base, importPath);
          if (existsSync(resolved) && existsSync(join(resolved, "index.js"))) {
            return `from ${quote}${importPath}/index.js${quote}`;
          }
          return `from ${quote}${importPath}.js${quote}`;
        }
      );
      if (patched !== content) {
        await writeFile(full, patched);
      }
    }
  }
}

try {
  await patchDir(root);
  console.log("Patched @tideorg/js extensionless imports");
} catch (e) {
  console.warn("Could not patch @tideorg/js:", e.message);
}
