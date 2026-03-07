export default function errorMiddleware(err,req,res,next){

    console.error(err)

    res.status(500).json({
        error:"Internal Server Error"
    })

}