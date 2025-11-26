import { defineConfig } from 'vite'
import solid from 'vite-plugin-solid'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

export default defineConfig({
  cacheDir: './.vite',
  build: {
    target: 'esnext',
    minify: false
  },
  plugins: [
    solid(),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    }
  },
  server: {
    port: 3001
  }
})
