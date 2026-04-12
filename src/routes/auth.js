import express from "express"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import fetch from "node-fetch"
import multer from "multer"
import crypto from "crypto"
import prisma from "../utils/prisma.js"
import authMiddleware from "../middleware/authMiddleware.js"
import { sendNewRegistrationAdminEmail, sendEmailVerificationCode, sendPasswordResetEmail } from "../utils/email.js"
import { logAudit } from "../utils/audit.js"

const router = express.Router()

const storage = multer.memoryStorage()

const upload = multer({
    storage,
    limits:{fileSize:2*1024*1024}
})

const generateAccessToken=(userId,role)=>{
    return jwt.sign(
        {sub:userId,role},
        process.env.JWT_SECRET,
        {expiresIn:"15m"}
    )
}

const generateRefreshToken=(userId)=>{
    return jwt.sign(
        {id:userId},
        process.env.JWT_REFRESH_SECRET,
        {expiresIn:"7d"}
    )
}

const ipLocationCache=new Map()

const formatDate=(date)=>{
    const d=new Date(date)
    const day=String(d.getDate()).padStart(2,"0")
    const month=String(d.getMonth()+1).padStart(2,"0")
    const year=d.getFullYear()
    return `${day}.${month}.${year}`
}

const cleanupExpiredTokens=async()=>{
    await prisma.refreshToken.deleteMany({
        where:{
            expiresAt:{lt:new Date()}
        }
    })
}

const enforceMaxDevices=async(userId,limit=3)=>{

    const tokensToRemove=await prisma.refreshToken.findMany({
        where:{userId},
        orderBy:{lastUsedAt:"desc"},
        skip:limit,
        select:{id:true}
    })

    if(tokensToRemove.length>0){

        await prisma.refreshToken.deleteMany({
            where:{id:{in:tokensToRemove.map(t=>t.id)}}
        })

    }

}

const getLocationFromIP=async(req)=>{

    const ip=
        req.headers["x-forwarded-for"]?.split(",")[0] ||
        req.ip

    if(!ip) return "Unknown"

    const cached=ipLocationCache.get(ip)

    if(cached && cached.expiresAt>Date.now())
        return cached.location

    try{

        const geo=await fetch(`https://ipapi.co/${ip}/json/`)
        const geoData=await geo.json()

        const location=`${geoData?.country_name ?? "Unknown"}, ${geoData?.city ?? ""}`

        ipLocationCache.set(ip,{
            location,
            expiresAt:Date.now()+86400000
        })

        return location

    }catch{
        return "Unknown"
    }

}

const getTrustedDomains = () => {
    const raw = process.env.TRUSTED_EMAIL_DOMAINS || ""
    return raw
        .split(",")
        .map((d)=>d.trim().toLowerCase())
        .filter(Boolean)
}

const getTeacherInviteCodes = () => {
    const raw = process.env.TEACHER_INVITE_CODES || ""
    return new Set(
        raw
            .split(",")
            .map((c)=>c.trim())
            .filter(Boolean)
    )
}

const computeRoleAndStatus = (normalizedEmail, role, inviteCode) => {
    const requestedRole = typeof role === "string" ? role.toLowerCase() : "student"
    const isTeacher = requestedRole === "teacher"

    const teacherInviteCodes = getTeacherInviteCodes()
    const trustedDomains = getTrustedDomains()

    const emailDomain = normalizedEmail.split("@")[1] || ""

    let dbRole = isTeacher ? "TEACHER" : "STUDENT"
    let status = "PENDING"

    if (isTeacher) {
        if (inviteCode && teacherInviteCodes.has(String(inviteCode).trim())) {
            status = "APPROVED"
        } else {
            status = "PENDING"
        }
    } else {
        if (trustedDomains.includes(emailDomain)) {
            status = "APPROVED"
        } else {
            status = "LIMITED"
        }
    }

    return { dbRole, status }
}

const generateEmailCode = () => {
    const n = Math.floor(100000 + Math.random() * 900000)
    return String(n)
}

const getClientIp = (req) => {
    return (
        req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
        req.ip ||
        "unknown"
    )
}

router.post("/register",async(req,res)=>{

    try{

        const {
            email,
            password,
            name,
            role,
            organization,
            profileUrl,
            inviteCode,
        }=req.body

        if(!email)
            return res.status(400).json({
                error:"Email и пароль обязательны"
            })

        const passwordStr = password != null ? String(password).trim() : ""
        if (!passwordStr || passwordStr.length < 6)
            return res.status(400).json({
                error:"Пароль должен быть не менее 6 символов"
            })
        const nameStr = name != null ? String(name).trim() : ""
        if (!nameStr || nameStr.length < 2)
            return res.status(400).json({
                error: "Имя обязательно"
            })
        const normalizedEmail = String(email).trim().toLowerCase()

        const existingUser=await prisma.user.findUnique({
            where:{email:normalizedEmail}
        })

        if(existingUser)
            return res.status(400).json({
                error:"Пользователь с таким email уже существует"
            })

        const code = generateEmailCode()
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000)

        await prisma.emailCode.create({
            data:{
                email: normalizedEmail,
                code,
                purpose: "register",
                expiresAt,
            }
        })

        await sendEmailVerificationCode(normalizedEmail, code)

        res.status(201).json({
            message:"Verification code sent"
        })

    }catch(error){

        console.error("REGISTER ERROR:",error)

        res.status(500).json({
            error:"Something went wrong"
        })

    }

})

router.post("/request-code", async (req, res) => {

    try{

        const {
            email,
            purpose,
        } = req.body || {}

        if (!email)
            return res.status(400).json({ error:"Email и пароль обязательны" })

        const normalizedEmail = String(email).trim().toLowerCase()
        const now = new Date()

        const code = generateEmailCode()
        const expiresAt = new Date(now.getTime() + 10 * 60 * 1000) // 10 минут

        await prisma.emailCode.create({
            data:{
                email: normalizedEmail,
                code,
                purpose: purpose || "login",
                expiresAt,
            }
        })

        await sendEmailVerificationCode(normalizedEmail, code)

        res.json({
            message:"Verification code sent",
        })

    }catch(e){

        console.error("REQUEST-CODE ERROR", e)
        res.status(500).json({ error:"Something went wrong" })

    }

})

router.post("/verify-email", async (req, res) => {

    try{

        const {
            email,
            code,
            password: registerPassword,
            name,
            role,
            organization,
            profileUrl,
            inviteCode,
        } = req.body || {}

        if (!email || !code)
            return res.status(400).json({ error:"Email и пароль обязательны" })

        const normalizedEmail = String(email).trim().toLowerCase()
        const codeStr = String(code).trim()

        const record = await prisma.emailCode.findFirst({
            where:{
                email: normalizedEmail,
                code: codeStr,
                consumedAt: null,
                expiresAt: { gt: new Date() },
            },
            orderBy:{ createdAt:"desc" },
        })

        if (!record)
            return res.status(401).json({ error:"Неверный email или пароль" })

        const mode = record.purpose || "login"

        let user = await prisma.user.findUnique({
            where:{ email: normalizedEmail }
        })

        if (mode === "login" && !user)
            return res.status(401).json({ error:"Неверный email или пароль" })

        if (mode === "register" && user)
            return res.status(400).json({ error:"Пользователь с таким email уже существует" })

        await prisma.emailCode.update({
            where:{ id: record.id },
            data:{ consumedAt: new Date() },
        })

        if (!user && mode === "register") {
            const rawPassword = registerPassword != null ? String(registerPassword).trim() : ""
            if (!rawPassword || rawPassword.length < 6) {
                return res.status(400).json({
                    error: "Пароль должен быть не менее 6 символов"
                })
            }

            const nameStr = name != null ? String(name).trim() : ""
            if (!nameStr || nameStr.length < 2) {
                return res.status(400).json({
                    error: "Имя обязательно"
                })
            }
            const passwordHash = await bcrypt.hash(rawPassword, 10)
            const { dbRole, status } = computeRoleAndStatus(normalizedEmail, role, inviteCode)
            user = await prisma.user.create({
                data:{
                    email: normalizedEmail,
                    password: passwordHash,
                    name: nameStr,
                    role: dbRole,
                    status,
                    organization: organization ? String(organization).trim() : null,
                    profileUrl: profileUrl ? String(profileUrl).trim() : null,
                    inviteCode: inviteCode ? String(inviteCode).trim() : null,
                }
            })

            if (dbRole === "TEACHER") {
                try {
                    await sendNewRegistrationAdminEmail(user)
                } catch (e) {
                    console.error("[auth/verify-email] Failed to send admin registration email", {
                        userId: user.id,
                        email: user.email,
                        error: e?.message,
                    })
                }
            }
        }

        if(user.status === "BLOCKED")
            return res.status(403).json({
                error:"Account is blocked"
            })
        if(user.status === "PENDING")
            return res.status(401).json({
                error:"Account is awaiting admin approval"
            })

        const accessToken=generateAccessToken(user.id,user.role)
        const refreshToken=generateRefreshToken(user.id)

        const device=req.headers["user-agent"] ?? "unknown"
        const location=await getLocationFromIP(req)

        await prisma.refreshToken.create({
            data:{
                token:refreshToken,
                userId:user.id,
                device,
                location,
                userAgent:device,
                lastUsedAt:new Date(),
                expiresAt:new Date(Date.now()+604800000)
            }
        })

        await enforceMaxDevices(user.id)
        await cleanupExpiredTokens()

        res.cookie("refreshToken",refreshToken,{
            httpOnly:true,
            secure:true,
            sameSite:"none",
            maxAge:604800000
        })

        res.json({
            token:accessToken,
            user:{
                id:user.id,
                email:user.email,
                name:user.name,
                role:user.role === "ADMIN" ? "admin" : user.role === "TEACHER" ? "teacher" : "student",
                status:user.status,
                createdAt:user.createdAt
            },
        })

    }catch(e){

        console.error("VERIFY-CODE ERROR", e)
        res.status(500).json({ error:"Server error" })

    }

})

router.post("/login",async(req,res)=>{

    try{

        const {email,password}=req.body

        if(!email || !password)
            return res.status(400).json({
                error:"Email и пароль обязательны"
            })

        const normalizedEmail = String(email).trim().toLowerCase()

        const user=await prisma.user.findUnique({
            where:{email:normalizedEmail}
        })

        if(!user){
            console.warn("[auth/login] 401: user not found", { email: normalizedEmail })
            return res.status(401).json({
                error:"Неверный email или пароль"
            })
        }
        if(user.status === "BLOCKED"){
            console.warn("[auth/login] 403: status BLOCKED", { userId: user.id, email: user.email })
            return res.status(403).json({
                error:"Account is blocked"
            })
        }
        if(user.status === "PENDING"){
            console.warn("[auth/login] 401: status PENDING", { userId: user.id, email: user.email })
            return res.status(401).json({
                error:"Account is awaiting admin approval"
            })
        }

        if (!user.password || user.password === "") {
            console.warn("[auth/login] 401: no password set", { userId: user.id, email: user.email })
            return res.status(401).json({
                error:"Please set your password using the “Forgot password” link, then log in."
            })
        }

        const validPassword=await bcrypt.compare(
            password,
            user.password
        )

        if(!validPassword){
            console.warn("[auth/login] 401: password mismatch", { userId: user.id, email: user.email })
            return res.status(401).json({
                error:"Неверный email или пароль"
            })
        }

        const accessToken=generateAccessToken(user.id,user.role)
        const refreshToken=generateRefreshToken(user.id)

        const device=req.headers["user-agent"] ?? "unknown"
        const location=await getLocationFromIP(req)

        const existingSession=await prisma.refreshToken.findFirst({
            where:{
                userId:user.id,
                device,
                location
            }
        })

        const isNewDevice=!existingSession

        await prisma.refreshToken.create({
            data:{
                token:refreshToken,
                userId:user.id,
                device,
                location,
                userAgent:device,
                lastUsedAt:new Date(),
                expiresAt:new Date(Date.now()+604800000)
            }
        })

        await enforceMaxDevices(user.id)
        await cleanupExpiredTokens()

        res.cookie("refreshToken",refreshToken,{
            httpOnly:true,
            secure:true,
            sameSite:"none",
            maxAge:604800000
        })

        res.json({
            token:accessToken,
            user:{
                id:user.id,
                email:user.email,
                name:user.name,
                role:user.role === "ADMIN" ? "admin" : user.role === "TEACHER" ? "teacher" : "student",
                status:user.status,
                createdAt:user.createdAt
            },
            device,
            location,
            isNewDevice
        })

    }catch(e){

        console.error("[auth/login] 500:", e)
        res.status(500).json({error:"Server error"})

    }

})

router.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body || {}

        if (!email) {
            return res.status(200).json({
                message: "If this email exists, password reset instructions have been sent",
            })
        }

        const normalizedEmail = String(email).trim().toLowerCase()

        const user = await prisma.user.findUnique({
            where: { email: normalizedEmail },
            select: { id: true, email: true },
        })

        if (user) {
            const token = crypto.randomBytes(32).toString("hex")
            const expiresAt = new Date(Date.now() + 30 * 60 * 1000)

            await prisma.passwordResetToken.create({
                data: {
                    userId: user.id,
                    token,
                    expiresAt,
                },
            })

            console.log("FORGOT-PASSWORD: sending reset email", {
                userId: user.id,
                email: user.email,
            })

            await sendPasswordResetEmail(user.email, token)

            console.log("FORGOT-PASSWORD: reset email queued", {
                userId: user.id,
                email: user.email,
            })

            const ip = getClientIp(req)
            const userAgent = req.headers["user-agent"] || "unknown"

            await logAudit(
                user.id,
                "PASSWORD_RESET_REQUEST",
                "PasswordReset",
                user.id,
                { email: user.email, ip, userAgent }
            )
        } else {
            const ip = getClientIp(req)
            const userAgent = req.headers["user-agent"] || "unknown"

            await logAudit(
                "anonymous",
                "PASSWORD_RESET_REQUEST_UNKNOWN_EMAIL",
                "PasswordReset",
                null,
                { email: normalizedEmail, ip, userAgent }
            )
        }

        res.status(200).json({
            message: "If this email exists, password reset instructions have been sent",
        })
    } catch (e) {
        console.error("POST /forgot-password", e)
        res.status(200).json({
            message: "If this email exists, password reset instructions have been sent",
        })
    }
})

router.get("/reset-password/validate", async (req, res) => {
    try {
        const token = String(req.query.token || "").trim()

        if (!token) {
            return res.status(400).json({ error: "Invalid or expired token" })
        }

        const record = await prisma.passwordResetToken.findUnique({
            where: { token },
            include: { user: true },
        })

        if (
            !record ||
            record.usedAt ||
            record.expiresAt < new Date()
        ) {
            return res.status(400).json({ error: "Invalid or expired token" })
        }

        return res.json({
            ok: true,
            email: record.user?.email ?? null,
        })
    } catch (e) {
        console.error("GET /reset-password/validate", e)
        return res.status(400).json({ error: "Invalid or expired token" })
    }
})

router.post("/reset-password", async (req, res) => {
    try {
        const { token, password } = req.body || {}

        if (!token || !password) {
            return res.status(400).json({ error: "Token and password are required" })
        }

        const newPasswordStr = String(password).trim()
        if (!newPasswordStr || newPasswordStr.length < 6) {
            return res.status(400).json({
                error: "Password must be at least 6 characters",
            })
        }

        const record = await prisma.passwordResetToken.findUnique({
            where: { token: String(token).trim() },
        })

        if (
            !record ||
            record.usedAt ||
            record.expiresAt < new Date()
        ) {
            await logAudit(
                "anonymous",
                "PASSWORD_RESET_TOKEN_INVALID",
                "PasswordReset",
                null,
                { token: "invalid_or_expired" }
            )

            return res.status(400).json({ error: "Invalid or expired token" })
        }

        const user = await prisma.user.findUnique({
            where: { id: record.userId },
        })

        if (!user) {
            return res.status(400).json({ error: "Invalid or expired token" })
        }

        const hashed = await bcrypt.hash(newPasswordStr, 10)

        await prisma.$transaction([
            prisma.user.update({
                where: { id: user.id },
                data: { password: hashed },
            }),
            prisma.passwordResetToken.update({
                where: { id: record.id },
                data: { usedAt: new Date() },
            }),
            prisma.passwordResetToken.updateMany({
                where: {
                    userId: user.id,
                    usedAt: null,
                    id: { not: record.id },
                },
                data: { usedAt: new Date() },
            }),
        ])

        const ip = getClientIp(req)
        const userAgent = req.headers["user-agent"] || "unknown"

        await logAudit(
            user.id,
            "PASSWORD_RESET_SUCCESS",
            "PasswordReset",
            user.id,
            { ip, userAgent }
        )

        return res.json({
            message: "Password has been reset successfully",
        })
    } catch (e) {
        console.error("POST /reset-password", e)
        return res.status(500).json({ error: "Something went wrong" })
    }
})

router.post("/refresh",async(req,res)=>{

    try{

        const refreshToken=req.cookies?.refreshToken

        if(!refreshToken)
            return res.status(401).json({
                message:"No refresh token"
            })

        const storedToken=await prisma.refreshToken.findUnique({
            where:{token:refreshToken}
        })

        if(!storedToken)
            return res.status(401).json({
                message:"Invalid refresh token"
            })

        if(storedToken.expiresAt<new Date()){

            await prisma.refreshToken.delete({
                where:{token:refreshToken}
            })

            return res.status(401).json({
                message:"Refresh token expired"
            })

        }

        const decoded=jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET
        )

        await prisma.refreshToken.delete({
            where:{token:refreshToken}
        })

        const newRefreshToken=generateRefreshToken(decoded.id)
        const newAccessToken=generateAccessToken(decoded.id)

        await prisma.refreshToken.create({
            data:{
                token:newRefreshToken,
                userId:decoded.id,
                expiresAt:new Date(Date.now()+604800000)
            }
        })

        res.cookie("refreshToken",newRefreshToken,{
            httpOnly:true,
            secure:true,
            sameSite:"none",
            maxAge:604800000
        })

        res.json({
            accessToken:newAccessToken
        })

    }catch{

        res.status(401).json({
            message:"Invalid refresh token"
        })

    }

})

router.post("/logout",async(req,res)=>{

    try{

        const refreshToken=req.cookies?.refreshToken

        if(refreshToken){

            await prisma.refreshToken.deleteMany({
                where:{token:refreshToken}
            })

        }

        res.clearCookie("refreshToken")

        res.json({
            message:"Logged out successfully"
        })

    }catch{

        res.status(500).json({
            message:"Logout failed"
        })

    }

})

router.get("/me",authMiddleware,async(req,res)=>{
    const user=await prisma.user.findUnique({
        where:{id:req.user.id},
        select:{
            id:true,
            email:true,
            name:true,
            role:true,
            status:true,
            createdAt:true,
            updatedAt:true
        }
    })
    if(!user) return res.status(404).json({ message:"User not found" })
    res.json(user)
})

router.put("/me",authMiddleware,async(req,res)=>{
    try {
        const { name } = req.body || {}
        const data = {}
        if (name !== undefined) data.name = String(name).trim() || null
        if (Object.keys(data).length === 0) return res.status(400).json({ message:"No fields to update" })
        const user = await prisma.user.update({
            where:{ id: req.user.id },
            data,
            select:{ id:true, email:true, name:true, role:true, createdAt:true }
        })
        res.json(user)
    } catch (e) {
        console.error("PUT /me", e)
        res.status(500).json({ message:"Update failed" })
    }
})

router.put("/change-password",authMiddleware,async(req,res)=>{
    try {
        const { currentPassword, newPassword } = req.body || {}
        if (!currentPassword || !newPassword)
            return res.status(400).json({ message:"currentPassword and newPassword required" })
        const newPasswordStr = String(newPassword).trim()
        if (newPasswordStr.length < 6)
            return res.status(400).json({ message:"New password must be at least 6 characters" })
        const user = await prisma.user.findUnique({ where:{ id: req.user.id } })
        if (!user) return res.status(404).json({ message:"User not found" })
        if (!user.password || user.password === "") {
            return res.status(400).json({
                message:"No password set. Use “Forgot password” to set one, then you can change it here.",
            })
        }
        const valid = await bcrypt.compare(currentPassword, user.password)
        if (!valid) return res.status(401).json({ message:"Current password is wrong" })
        const hashed = await bcrypt.hash(newPasswordStr, 10)
        await prisma.user.update({
            where:{ id: req.user.id },
            data:{ password: hashed }
        })
        res.json({ message:"Password updated" })
    } catch (e) {
        console.error("PUT /change-password", e)
        res.status(500).json({ message:"Change password failed" })
    }
})

router.put("/change-email",authMiddleware,async(req,res)=>{
    try {
        const { password, newEmail } = req.body || {}
        if (!password || !newEmail)
            return res.status(400).json({ message:"password and newEmail required" })
        const normalized = String(newEmail).trim().toLowerCase()
        const user = await prisma.user.findUnique({ where:{ id: req.user.id } })
        if (!user) return res.status(404).json({ message:"User not found" })
        if (!user.password || user.password === "") {
            return res.status(400).json({
                message:"No password set. Use “Forgot password” first, then you can change email.",
            })
        }
        const valid = await bcrypt.compare(password, user.password)
        if (!valid) return res.status(401).json({ message:"Password is wrong" })
        const existing = await prisma.user.findUnique({ where:{ email: normalized } })
        if (existing) return res.status(409).json({ message:"Email already in use" })
        await prisma.user.update({
            where:{ id: req.user.id },
            data:{ email: normalized }
        })
        res.json({ message:"Email updated", email: normalized })
    } catch (e) {
        console.error("PUT /change-email", e)
        res.status(500).json({ message:"Change email failed" })
    }
})

router.delete("/delete-account",authMiddleware,async(req,res)=>{
    try {
        const { password } = req.body || {}
        if (!password) return res.status(400).json({ message:"password required" })
        const user = await prisma.user.findUnique({ where:{ id: req.user.id } })
        if (!user) return res.status(404).json({ message:"User not found" })
        const valid = await bcrypt.compare(password, user.password)
        if (!valid) return res.status(401).json({ message:"Password is wrong" })
        await prisma.user.delete({ where:{ id: req.user.id } })
        res.clearCookie("refreshToken")
        res.json({ message:"Account deleted" })
    } catch (e) {
        console.error("DELETE /delete-account", e)
        res.status(500).json({ message:"Delete account failed" })
    }
})

router.post("/avatar", authMiddleware, upload.single("avatar"), async (req, res) => {
    try {
        if (!req.file || !req.file.buffer)
            return res.status(400).json({ message: "No file uploaded" })
        await prisma.user.update({
            where: { id: req.user.id },
            data: { avatar: req.file.buffer }
        })
        res.json({ message: "Avatar updated" })
    } catch (e) {
        console.error("POST /avatar", e)
        res.status(500).json({ message: "Avatar upload failed" })
    }
})

router.get("/avatar", authMiddleware, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user.id },
            select: { avatar: true }
        })
        if (!user || !user.avatar) return res.status(404).json({ message: "No avatar" })
        res.set("Content-Type", "image/jpeg")
        res.send(user.avatar)
    } catch (e) {
        console.error("GET /avatar", e)
        res.status(500).json({ message: "Failed to get avatar" })
    }
})

router.post("/logout-all",authMiddleware,async(req,res)=>{

    await prisma.refreshToken.deleteMany({
        where:{userId:req.user.id}
    })

    res.clearCookie("refreshToken")

    res.json({
        message:"Logged out from all devices"
    })

})

router.get("/sessions",authMiddleware,async(req,res)=>{

    await cleanupExpiredTokens()

    const sessions = await prisma.refreshToken.findMany({
        where: { userId: req.user.id },
        orderBy: { createdAt: "desc" },
        take: 100,
    });

    const formatted=sessions.map(session=>({

        ...session,
        createdAtFormatted:formatDate(session.createdAt),
        lastUsedAtFormatted:formatDate(session.lastUsedAt),
        expiresAtFormatted:formatDate(session.expiresAt)

    }))

    res.json({sessions:formatted})

})

router.delete("/sessions/:id",authMiddleware,async(req,res)=>{

    const sessionId=req.params.id

    const result=await prisma.refreshToken.deleteMany({
        where:{
            id:sessionId,
            userId:req.user.id
        }
    })

    if(result.count===0)
        return res.status(404).json({
            message:"Session not found"
        })

    res.json({
        message:"Session terminated"
    })

})

export default router