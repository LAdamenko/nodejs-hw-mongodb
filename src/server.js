import express from 'express';
import pino from 'pino-http';
import cors from 'cors';
import dotenv from "dotenv";
import { getAllContacts, getContactById } from './services/contacts.js';

dotenv.config();

export function setupServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(
    pino({
      transport: {
        target: 'pino-pretty',
      },
    }),
  );

  app.use(cors());

  app.get('/contacts', async (req, res) => {
    const contacts = await getAllContacts();

    res.status(200).json({
      status: 200,
      message: "Successfully found contacts!",
      data: contacts,
    });
  });

  app.get('/contacts/:contactId', async (req, res) => {
    try {
    const { contactId } = req.params;
    const contact = await getContactById(contactId);

	if (!contact) {
	  res.status(404).json({
		  message: 'Contact not found',
	  });
	  return;
      }
      res.status(200).json({
      status: 200,
      message: `Successfully found contact with id ${contactId}!`,
      data: contact,
    });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
  });

  app.use((req, res, next) => {
    res.status(404).send('Not found');
  });

  app.use((error, req, res, next) => {
    res.status(500).send('Internal Server Error');
  });

  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
}
