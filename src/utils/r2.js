import crypto from "crypto"
import path from "path"
import {
    S3Client,
    PutObjectCommand,
    GetObjectCommand,
    DeleteObjectCommand,
} from "@aws-sdk/client-s3"
import { getSignedUrl } from "@aws-sdk/s3-request-presigner"

const bucket = process.env.R2_BUCKET

export const r2 = new S3Client({
    region: "auto",
    endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    },
})

export function makeStorageKey(folder, originalName = "file") {
    const ext = path.extname(originalName).toLowerCase()
    const name = crypto.randomUUID()

    return `${folder}/${name}${ext}`
}

export async function uploadBufferToR2({ key, buffer, contentType }) {
    await r2.send(
        new PutObjectCommand({
            Bucket: bucket,
            Key: key,
            Body: buffer,
            ContentType: contentType || "application/octet-stream",
        })
    )

    return key
}

export async function deleteFromR2(key) {
    if (!key) return

    await r2.send(
        new DeleteObjectCommand({
            Bucket: bucket,
            Key: key,
        })
    )
}

export async function getDownloadUrlFromR2(key, fileName) {
    const command = new GetObjectCommand({
        Bucket: bucket,
        Key: key,
        ResponseContentDisposition: fileName
            ? `attachment; filename="${encodeURIComponent(fileName)}"`
            : undefined,
    })

    return getSignedUrl(r2, command, {
        expiresIn: 60 * 5,
    })
}