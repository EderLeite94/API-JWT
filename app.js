require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const app = express()
const port = process.env.PORT || 3000
//Config json response
app.use(express.json())

//Models
const User = require('./models/User')

app.listen(port, () => {
    console.info("Aplicação rodando em http://localhost:3000")
})

app.get('/', (req, res) => {
    res.status(200).json({ msg: "Bem vindo a API!" })
})

//Private Route
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id

    //check if user exists
    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado!" })
    }
    res.status(200).json({ user })
})

function checkToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ msg: "Acesso negado!" })
    }

    try {
        const secret = process.env.SECRET
        
        jwt.verify(token, secret)

        next()
    } catch (error) {
        res.status(400).json({msg:"Token inválido!"})
    }

}
//Register user
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body

    if (!name) {
        return res.status(422).json({ msg: "O nome é obrigatório!" })
    }
    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório!" })
    }
    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória!" })
    }
    if (password !== confirmpassword) {
        return res.status(422).json({ msg: "As senhas nao conferem!" })
    }
    //check if user exists
    const userExists = await User.findOne({ email: email })

    if (userExists) {
        return res.status(422).json({ msg: "Por favor utilize outro e-mail!" })
    }

    //create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })
    try {
        await user.save()
        res.status(201).json({ msg: 'Usuário criado com sucesso!' })
    } catch (error) {
        console.log(error)
        res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!' })

    }
})

//Login User
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body

    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatorio!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatorio!' })
    }
    //check if user exists
    const user = await User.findOne({ email: email })

    if (!user) {
        return res.status(404).json({ msg: 'Usuário nao encontrado!' })
    }
    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(422).json({ msg: 'Senha invalida!' })
    }

    try {
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id,
        },
            secret,
        )

        res.status(200).json({ msg: 'Autenticação realizada com sucesso', token })

    } catch (error) {
        console.log(error)
        res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!' })
    }

})

const DB_USER = process.env.DB_USER
const DB_PASSWORD = encodeURIComponent(process.env.DB_PASSWORD)
mongoose.connect(`mongodb+srv://${DB_USER}:${DB_PASSWORD}@apicluster.dbu0bpy.mongodb.net/usuarios?retryWrites=true&w=majority`)
    .then(() => {
        console.log('Conectado ao MongoDB!')
        app.listen(8080)

    })
    .catch((err) => console.log(err))
