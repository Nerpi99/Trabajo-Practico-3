const jwt = require('jsonwebtoken')
const bcryptjs = require('bcryptjs')
const conexion = require('../database/db')
const {promisify} = require('util')

//metodo para registrarnos 

exports.register = async(req, res)=>{
    try{
        const name = req.body.name
        const user = req.body.user
        const pass = req.body.pass
        let passHash = await bcryptjs.hash(pass, 8)

        conexion.query('INSERT INTO users SET ?',{username:user, name:name, pass:passHash}, (error, results)=>{
            if(error){console.log(error)}
            res.redirect('/')
        })
    }catch(error){
        console.log(error)
    }
    
    //console.log(passHash)


}
exports.login =  async(req, res)=>{
    try{
        const user = req.body.user
        const pass = req.body.pass
        if(!user || !pass ){
            res.render('login',{
                alert:true, 
                alertTitle:"Advertencia",
                alertMessage:"Ingrese un usuario y password",
                alertIcon:"Info",
                showConfirmButton:true, 
                timer:false,
                ruta:"login"
            })
        }else{
            conexion.query('SELECT * FROM users WHERE username = ?', [user], async (error, results)=>{
                if(results.length == 0 || ! (await bcryptjs.compare(pass, results[0].pass))){
                    res.render('login',{
                        alert:true, 
                        alertTitle:"Error",
                        alertMessage:"Usuario y/o Password incorrectas",
                        alertIcon:"",
                        showConfirmButton:true, 
                        timer:false,
                        ruta:"login"
                    })  
                }else{
                    //inicio ok
                    const id = results[0].id
                    const token = jwt.sign({id:id}, process.env.JWT_SECRETO,{
                        expiresIn: process.env.JWT_TIEMPO_EXPIRA
                    } )
                   // const token = jwt.sign({id: id}, process.env.JWT_SECRETO)
                   console.log("TOKEN: "+token+"para el USUARIO: "+user)

                   const cookieOptions = {
                       expires: new Date(Date.now()+process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
                       httpOnly: true
                   }
                   res.cookie('jwt', token, cookieOptions)
                   res.render('login', {

                    alert:true, 
                    alertTitle:"Conexion Exitosa",
                    alertMessage:"Login correcto!!",
                    alertIcon:"success",
                    showConfirmButton:false, 
                    timer: 800,
                    ruta:''


                   })
                }
            })
        }
    }catch(error){

        console.log(error)

    }
}

exports.isAuthenticated = async(req, res,next)=>{
    if(req.cookies.jwt){
        try {
            const decodificada = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRETO)
            conexion.query('SELECT * FROM users WHERE id=?', [decodificada.id], (error, results)=>{
                if(!results){return next()}
                req.user = results[0]
                return next()
            })
        } catch (error) {
            console.log(error)
            return next()
        }
    }else{
        res.redirect('/login')
    }
}

exports.logout = (req, res)=>{
    res.clearCookie('jwt')
    return res.redirect('/')
}