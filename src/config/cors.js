const DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "https://konilai.space",
    "https://www.konilai.space",
    "https://elasweb.vercel.app",
]

function normalizeOrigin(value) {
    const raw = String(value || "").trim()
    if (!raw) return null

    try {
        return new URL(raw).origin
    } catch {
        return raw.replace(/\/$/, "")
    }
}

export function getAllowedOrigins() {
    const configuredOrigins = [
        process.env.CORS_ORIGIN,
        process.env.WS_ALLOWED_ORIGINS,
    ]
        .filter(Boolean)
        .flatMap((value) => String(value).split(","))
        .map(normalizeOrigin)
        .filter(Boolean)

    return Array.from(
        new Set([
            ...DEFAULT_ALLOWED_ORIGINS,
            ...configuredOrigins,
        ])
    )
}
