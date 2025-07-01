const express = require('express')
const dotenv = require('dotenv')
const path = require('path')
const { generateToken, decodeToken } = require('./app/services/authService')
dotenv.config({
    path: path.join(__dirname, '.env')
})



const app = express()
app.use(express.urlencoded({ extended: true })),
app.use(express.json({ limit: '10mb' }))

app.post('/api/v1/auth/login', (req, res) => {

    const { email, password } = req.body 

    const token = generateToken({ email })

    res.status(200).json({ token })

})

,
app.delete('/api/v1/users/delete', (req, res) => {
    console.log(req.headers)
    const authorization = req.headers.authorisation
    const token = authorization.split(' ')[1]
    // Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFudG9pbmVAZ21haWwuY29tIiwiaWF0IjoxNzUxMjgwNjk5LCJleHAiOjE3NTEyODQyOTl9.xUX3fmzE54AedWWbcgL9eIuJXWjYYw9qdK9yVYjbLbc
    const { email } =decodeToken(token)
    res.status(200).json({ email })

})


app.set('port', process.env.PORT)
app.set('host', process.env.HOST)
app.listen(app.get('port'), () => {
    console.log(`🚀Server running at ${app.get('host')}: ${app.get('port')}`)
})
