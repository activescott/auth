// Load .env into process.env for server code (SMTP settings, secrets).
// Existing environment variables always win over .env values.
import "dotenv/config"
import { reactRouter } from "@react-router/dev/vite"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from "vite"

export default defineConfig({
  plugins: [tailwindcss(), reactRouter()],
  resolve: {
    tsconfigPaths: true,
  },
})
