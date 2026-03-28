import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/review':   'http://localhost:8000',
      '/status':   'http://localhost:8000',
      '/results':  'http://localhost:8000',
      '/stream':   'http://localhost:8000',
      '/webhook':  'http://localhost:8000',
    }
  }
})