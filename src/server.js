import cookieParser from 'cookie-parser';
import express from 'express';
import pino from 'pino-http';
import cors from 'cors';
import authRouters from './routers/auth.js';
import contactsRouter from './routers/contacts.js';
import dotenv from "dotenv";
import { errorHandler } from './middlewares/errorHandler.js';
import { notFoundHandler } from './middlewares/notFoundHandler.js';
import { UPLOAD_DIR } from './constants/index.js';
import { swaggerDocs } from './middlewares/swaggerDocs.js';

dotenv.config();

export function setupServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 4000;

  app.use(
    pino({
      transport: {
        target: 'pino-pretty',
      },
    }),
  );

  app.use(cors());

  app.use(express.json());

  app.use('/uploads', express.static(UPLOAD_DIR));
  app.use('/api-docs', swaggerDocs());

  app.use(cookieParser());

  app.use('/uploads', express.static(UPLOAD_DIR));

  app.use(authRouters);

  app.use(contactsRouter);

  app.use('*', notFoundHandler);

  app.use(errorHandler);

  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
}
