export default function notFoundMiddleware(req, res) {
    res.status(404).json({ error: "Not found", path: req.originalUrl })
}
