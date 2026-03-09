import jwt from "jsonwebtoken"
import prisma from "../utils/prisma.js"

export default async function authMiddleware(req,res,next){

    try{

        const authHeader =
            req.headers.authorization || req.headers.Authorization

        if(!authHeader || !authHeader.startsWith("Bearer "))
            return res.status(401).json({error:"No token provided"})

        const token = authHeader.split(" ")[1]

        let decoded

        try{

            decoded = jwt.verify(token,process.env.JWT_SECRET)

        }catch(err){

            if(err.name === "TokenExpiredError")
                return res.status(401).json({error:"Token expired"})

            return res.status(401).json({error:"Invalid token"})

        }

        if(!decoded?.sub)
            return res.status(401).json({error:"Invalid token payload"})

        const user = await prisma.user.findUnique({
            where:{id:decoded.sub},
            select:{
                id:true,
                email:true,
                role:true,
                name:true,
                status:true
            }
        })

        if(!user)
            return res.status(401).json({error:"User not found"})
        if(user.status === "BLOCKED")
            return res.status(403).json({error:"Account is blocked"})
        if(user.status === "PENDING")
            return res.status(403).json({error:"Account is awaiting admin approval"})

        req.user = {
            id: user.id,
            userId: user.id,
            email: user.email,
            role: user.role,
            name: user.name,
        }
        req.userId = user.id

        next()

    }catch(err){

        console.error("AUTH ERROR",err)

        res.status(401).json({error:"Authentication failed"})

    }

}