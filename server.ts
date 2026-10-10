import express from 'express';
import { createServer as createViteServer } from 'vite';
import net from 'node:net';
import path from 'path';
import { apiRouter } from './server/routes/api';

async function getAvailablePort(startPort: number, maxAttempts = 20): Promise<number> {
  for (let offset = 0; offset < maxAttempts; offset += 1) {
    const port = startPort + offset;
    const isAvailable = await new Promise<boolean>((resolve) => {
      const tester = net.createServer();

      tester.once('error', () => resolve(false));
      tester.once('listening', () => {
        tester.close(() => resolve(true));
      });

      tester.listen(port, '0.0.0.0');
    });

    if (isAvailable) {
      return port;
    }
  }

  throw new Error(`No free port available starting from ${startPort}`);
}

async function startServer() {
  const app = express();
  const preferredPort = Number.parseInt(process.env.PORT ?? '3000', 10);
  const PORT = Number.isFinite(preferredPort) && preferredPort > 0 ? preferredPort : 3000;

  app.use(express.json());

  // Mount API Router
  app.use('/api', apiRouter);

  // Health check endpoint
  app.get('/healthz', (req, res) => {
    res.json({ status: 'healthy', platform: 'SecureGate AI', timestamp: new Date().toISOString() });
  });

  if (process.env.NODE_ENV === 'production') {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    // Mount Vite middleware in development
    const vite = await createViteServer({
      server: { middlewareMode: true, host: '0.0.0.0' },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  }

  const portToUse = await getAvailablePort(PORT);

  app.listen(portToUse, '0.0.0.0', () => {
    console.log(`[SecureGate AI] DevSecOps Server running on http://localhost:${portToUse}`);
    console.log(`[SecureGate AI] API endpoints mounted at /api/*`);
  });
}

startServer().catch((err) => {
  console.error('[SecureGate AI] Server failed to start:', err);
  process.exit(1);
});
