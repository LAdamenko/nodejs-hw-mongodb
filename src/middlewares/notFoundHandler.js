export const notFoundHandler = (_req, res, _next) => {
    res.status(404).send('Route not found');
  };
