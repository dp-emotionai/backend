import express from "express"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import fetch from "node-fetch"
import multer from "multer"
import prisma from "../utils/prisma.js"
import authMiddleware from "../middleware/authMiddleware.js"
import { sendNewRegistrationAdminEmail } from "../utils/email.js"
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

        if(!email || !password)
            return res.status(400).json({
                error:"Email и пароль обязательны"
            })

        if(password.length<6)
            return res.status(400).json({
                error:"Пароль должен быть не менее 6 символов"
            })

        const normalizedEmail=email.trim().toLowerCase()

        const existingUser=await prisma.user.findUnique({
            where:{email:normalizedEmail}
        })

        if(existingUser)
            return res.status(400).json({
                error:"Пользователь с таким email уже существует"
            })

        const hashedPassword=await bcrypt.hash(password,10)

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

        const user=await prisma.user.create({
            data:{
                email:normalizedEmail,
                password:hashedPassword,
                name:name ? String(name).trim() : null,
                role:dbRole,
                status,
                organization: organization ? String(organization).trim() : null,
                profileUrl: profileUrl ? String(profileUrl).trim() : null,
                inviteCode: inviteCode ? String(inviteCode).trim() : null,
            }
        })

        // уведомление админу о новой регистрации (best-effort)
        try{
            await sendNewRegistrationAdminEmail(user)
        }catch(e){
            console.error("EMAIL new registration failed",e)
        }

        // запись в аудит
        try{
            await logAudit(
                null,
                "user.registered",
                "User",
                user.id,
                { email:user.email, role:user.role, status:user.status }
            )
        }catch(e){
            console.error("AUDIT new registration failed",e)
        }

        res.status(201).json({
            message:"Registration successful",
            user:{
                id:user.id,
                email:user.email,
                name:user.name,
                role:dbRole === "ADMIN" ? "admin" : dbRole === "TEACHER" ? "teacher" : "student",
                status:user.status,
                createdAt:user.createdAt
            }
        })

    }catch(error){

        console.error("REGISTER ERROR:",error)

        res.status(500).json({
            error:"Something went wrong"
        })

    }

})

router.post("/login",async(req,res)=>{

    try{

        const {email,password}=req.body

        if(!email || !password)
            return res.status(400).json({
                error:"Email и пароль обязательны"
            })

        const user=await prisma.user.findUnique({
            where:{email:email.trim().toLowerCase()}
        })

        if(!user)
            return res.status(401).json({
                error:"Неверный email или пароль"
            })
        if(user.status === "BLOCKED")
            return res.status(403).json({
                error:"Account is blocked"
            })
        if(user.status === "PENDING")
            return res.status(403).json({
                error:"Account is awaiting admin approval"
            })

        const validPassword=await bcrypt.compare(
            password,
            user.password
        )

        if(!validPassword)
            return res.status(401).json({
                error:"Неверный email или пароль"
            })

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

    }catch{

        res.status(500).json({error:"Server error"})

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
        if (newPassword.length < 6)
            return res.status(400).json({ message:"New password must be at least 6 characters" })
        const user = await prisma.user.findUnique({ where:{ id: req.user.id } })
        if (!user) return res.status(404).json({ message:"User not found" })
        const valid = await bcrypt.compare(currentPassword, user.password)
        if (!valid) return res.status(401).json({ message:"Current password is wrong" })
        const hashed = await bcrypt.hash(newPassword, 10)
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
        const normalized = newEmail.trim().toLowerCase()
        const user = await prisma.user.findUnique({ where:{ id: req.user.id } })
        if (!user) return res.status(404).json({ message:"User not found" })
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