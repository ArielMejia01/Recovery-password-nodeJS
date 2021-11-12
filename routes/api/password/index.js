const {v4: uuidv4, v4} = require('uuid');
const mailSender = require('../../../utils/mailer');
let router = express.Router();
const express = require("express");
const jwt = require("jsonwebtoken");

let PassModelClass = require('./password.model.js');
let PassModel = new PassModelClass();

router.post('/login', async (req, res, next)=>{
    try {
        const {email, pswd} = req.body;
        //Validar los datos
        let userLogged = await PassModel.getByEmail(email);
        if (userLogged) {
            const isPswdOk = await PassModel.comparePassword(pswd, userLogged.password);
            if (isPswdOk) {
                // podemos validar la vigencia de la contraseña
                delete userLogged.password;
                delete userLogged.oldpasswords;
                delete userLogged.lastlogin;
                delete userLogged.lastpasswordchange;
                delete userLogged.passwordexpires;
                let payload = {
                jwt: jwt.sign(
                    {
                        email: userLogged.email,
                        _id: userLogged._id,
                        roles: userLogged.roles
                    },
                    process.env.JWT_SECRET,
                    {expiresIn:'1d'}
                ),
                user: userLogged
            };
            return res.status(200).json(payload);
        }
    }
    console.log({email, userLogged});
    return res.status(400).json({msg: "Credenciales no son Válidas"});
    } catch (ex) {
        console.log(ex);
        res.status(500).json({"msg":"Error"});
    }
    router.post('/signin', async (req, res, next) => {
        try {
            const {email, pswd} = req.body;
            let userAdded = await SecModel.createNewUser(email, pswd);
            delete userAdded.password;
            console.log(userAdded);
            res.status(200).json({"msg":"Usuario Creado Satisfactoriamente"});
        } catch (ex) {
            console.log(ex);
            res.status(500).json({"msg":"Error"});
        }
    });

    router.get('/',(req, res, next)=>{
        res.status(200).json({msg:"Password"})
    })

    router.post('/writepassword', async (req, res)=>{
        try {
            const {email} = res.body;
            let uId = v4();
            let insertUId = await PassModel.insertUId(email, uId)
            console.log(inserUId);
            mailSender(
                email,
                "Recovery Password",
                `<a>http://localhost:3000/api/password/restorepassword/${uId}</a>`
            )
            res.status(200).json({"msg":"Send a email"});

        } catch (err) {
            res.status(500).json({"msg": "Error en su solicitud" +err});
        }
    })

    router.post('/restorepassword/:id', async(req, res)=>{
        try {
            const {id}=req.params;
            const {passwordNew} = req.body;
            const passwordUpdate = await PassModel.passwordSwitch(id, passwordNew);
            console.log(passwordUpdate);
            res.status(200).json({msg: "Exito en cambio de password"})
        } catch (err) {
            res.status(500).json({"msg":"Error cambio de contrasenia" +err});
        }
    })
});

module.exports = router;
