const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
const path = require('path')
dotenv.config({
    path: path.join(__dirname, '../../.env')
})

const authService = {

    generateToken(payload){
        const token = jwt.sign(payload, process.env.SECRET_KEY, { algorithm: 'HS256', expiresIn: '1h'})
        return token
    },


    decodeToken(tokenToDecode){
        try {
            const decoded = jwt.verify(tokenToDecode, process.env.SECRET_KEY)
            return decoded
        } catch(err){
            return {}
        }

    }


}

module.exports = authService