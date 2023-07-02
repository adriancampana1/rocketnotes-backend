const knex = require('../database/knex');
const AppError = require('../utils/AppError');
const { compare } = require('bcryptjs');
const authConfig = require('../configs/auth');
const { sign } = require('jsonwebtoken');

class SessionsControllers {
    async create(request, response) {
        const { email, password } = request.body;

        // busca os dados do usuário cadastrados no banco de dados
        const user = await knex('users').where({ email }).first();

        // verifica se os dados inseridos correspondem a um usuário cadastrado no banco de dados
        if (!user) {
            throw new AppError('E-mail e/ou senha incorreta', 401);
        }

        // compara se a senha inserida pelo usuário no Login é igual à senha cadastrada no banco de dados
        const passwordMatched = await compare(password, user.password);

        // verifica se a senha inserida no Login corresponde a um usuário no banco de dados
        if (!passwordMatched) {
            throw new AppError('E-mail e/ou senha incorreta', 401);
        }

        const { secret, expiresIn } = authConfig.jwt;
        const token = sign({}, secret, {
            subject: String(user.id),
            expiresIn,
        });

        return response.json({ user, token });
    }
}

module.exports = SessionsControllers;
