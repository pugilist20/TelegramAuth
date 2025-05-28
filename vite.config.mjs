import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
    plugins: [
        tailwindcss(),
    ],
    server: {
        host: true,
        port: 5173,
        allowedHosts: 'all',

        proxy: {
            '^/$': {
                target: 'http://localhost:8080',
                changeOrigin: true,
            }
        }
    },
    build: {
        outDir: 'src/main/resources/static',
        emptyOutDir: true,
    },
})
