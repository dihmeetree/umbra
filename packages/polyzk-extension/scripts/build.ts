import { copyFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

const rootDir = join(import.meta.dir, "..");
const srcDir = join(rootDir, "src");
const distDir = join(rootDir, "dist");
const iconsDir = join(rootDir, "icons");

// Ensure dist directory exists
if (!existsSync(distDir)) {
  mkdirSync(distDir, { recursive: true });
}

// Copy static files
const staticFiles = [
  { src: join(srcDir, "popup.html"), dest: join(distDir, "popup.html") },
  { src: join(srcDir, "popup.css"), dest: join(distDir, "popup.css") },
  { src: join(srcDir, "content.css"), dest: join(distDir, "content.css") },
  { src: join(rootDir, "manifest.json"), dest: join(distDir, "manifest.json") },
];

for (const file of staticFiles) {
  if (existsSync(file.src)) {
    copyFileSync(file.src, file.dest);
    console.log(`Copied: ${file.src} -> ${file.dest}`);
  }
}

// Copy icons directory
const distIconsDir = join(distDir, "icons");
if (!existsSync(distIconsDir)) {
  mkdirSync(distIconsDir, { recursive: true });
}

if (existsSync(iconsDir)) {
  const iconSizes = ["16", "32", "48", "128"];
  for (const size of iconSizes) {
    const iconFile = `icon${size}.png`;
    const src = join(iconsDir, iconFile);
    const dest = join(distIconsDir, iconFile);
    if (existsSync(src)) {
      copyFileSync(src, dest);
      console.log(`Copied icon: ${iconFile}`);
    }
  }
}

console.log("Build complete!");
