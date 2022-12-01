import express from 'express';

import chatAPI from './chatAPI.js'

const PORT = 3001;

const app = express();
app.use(express.json());
app.use('/chat', chatAPI);
app.listen(PORT, () => console.log(`Server listening on PORT: ${PORT}`))