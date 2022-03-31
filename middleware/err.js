function errorHandler(err, req, res, next) {
  res.status(err.statusCode || 500).json({
    success: false,
    error: err.message,
  });
}

module.exports = errorHandler;
