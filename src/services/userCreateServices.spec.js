const UserCreateServices = require('./UserCreateServices');
const UserRepositoryInMemory = require('../repositories/UserRepositoryInMemory');

const AppError = require('../utils/AppError');

describe('UserCreateService', () => {
    let userRepositoryInMemory = null;
    let userCreateService = null;

    beforeEach(() => {
        userRepositoryInMemory = new UserRepositoryInMemory();
        userCreateService = new UserCreateServices(userRepositoryInMemory);
    });

    it('user should be create', async () => {
        const user = {
            name: 'User test',
            email: 'usertest@gmail.com',
            password: '123',
        };

        const userCreate = await userCreateService.execute(user);

        expect(userCreate).toHaveProperty('id');
    });

    it('user not should be create with exists email', async () => {
        const user1 = {
            name: 'User Test 1',
            email: 'user@test.com',
            password: '123',
        };

        const user2 = {
            name: 'User Test 2',
            email: 'user@test.com',
            password: '456',
        };

        await userCreateService.execute(user1);
        await expect(userCreateService.execute(user2)).rejects.toEqual(
            new AppError('Este e-mail já está em uso!')
        );
    });
});
